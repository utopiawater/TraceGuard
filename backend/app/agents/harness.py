from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Set, Type

from pydantic import BaseModel

from app.contracts import AgentResult, AgentTask
from app.contracts.agents import ToolCallSummary


class ModelClient(Protocol):
    def complete_json(self, role: str, prompt_version: str, payload: dict, schema: dict) -> dict: ...


@dataclass(frozen=True)
class AgentDefinition:
    role: str
    prompt_version: str
    allowed_tools: Set[str]


class AgentRegistry:
    def __init__(self, definitions: Iterable[AgentDefinition]) -> None:
        self._definitions = {item.role: item for item in definitions}

    def get(self, role: str) -> AgentDefinition:
        if role not in self._definitions:
            raise KeyError("unregistered agent role: %s" % role)
        return self._definitions[role]


@dataclass
class Tool:
    name: str
    handler: Callable[[dict], dict]
    arguments_model: Optional[Type[BaseModel]] = None
    read_only: bool = True


class ToolGateway:
    def __init__(self, tools: Iterable[Tool]) -> None:
        self._tools = {tool.name: tool for tool in tools}

        self._audit: Dict[str, List[ToolCallSummary]] = {}

    @staticmethod
    def _refs(value: Any) -> List[str]:
        refs: Set[str] = set()
        def visit(item: Any) -> None:
            if isinstance(item, dict):
                for key, child in item.items():
                    if key.endswith("_id") and isinstance(child, str):
                        refs.add(child)
                    elif key.endswith("_ids") and isinstance(child, list):
                        refs.update(str(ref) for ref in child)
                    else:
                        visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)
        visit(value)
        return sorted(refs)[:100]

    def invoke(self, task: AgentTask, registry: AgentRegistry, name: str, arguments: dict) -> dict:
        definition = registry.get(task.agent_role)
        if len(self._audit.get(task.task_id, [])) >= task.constraints.max_steps:
            self._audit.setdefault(task.task_id, []).append(ToolCallSummary(tool=name, input_summary=arguments, output_refs=[], status="denied"))
            raise RuntimeError("agent max_steps exceeded")
        if name not in definition.allowed_tools or name not in task.allowed_tools:
            self._audit.setdefault(task.task_id, []).append(ToolCallSummary(tool=name, input_summary=arguments, output_refs=[], status="denied"))
            raise PermissionError("tool is outside the task scope")
        tool = self._tools.get(name)
        if not tool or (task.constraints.read_only and not tool.read_only):
            self._audit.setdefault(task.task_id, []).append(ToolCallSummary(tool=name, input_summary=arguments, output_refs=[], status="denied"))
            raise PermissionError("tool is unavailable or not read-only")
        try:
            validated = tool.arguments_model.model_validate(arguments).model_dump(mode="json") if tool.arguments_model else arguments
            result = tool.handler(validated)
            self._audit.setdefault(task.task_id, []).append(ToolCallSummary(tool=name, input_summary=validated, output_refs=self._refs(result), status="succeeded"))
            return result
        except Exception:
            self._audit.setdefault(task.task_id, []).append(ToolCallSummary(tool=name, input_summary=arguments, output_refs=[], status="failed"))
            raise

    def audit_for(self, task_id: str) -> List[ToolCallSummary]:
        return list(self._audit.get(task_id, []))

    def clear_audit(self, task_id: str) -> None:
        self._audit.pop(task_id, None)


class EvidenceValidator:
    def validate(self, result: AgentResult, evidence_ids: Set[str]) -> List[str]:
        errors = []
        for index, finding in enumerate(result.findings):
            if not finding.evidence_ids:
                errors.append("finding[%d] has no evidence" % index)
            missing = set(finding.evidence_ids) - evidence_ids
            if missing:
                errors.append("finding[%d] references missing evidence: %s" % (index, sorted(missing)))
        return errors


class Orchestrator:
    """Explicit harness boundary. Execution is enabled when a ModelClient is configured."""

    def __init__(self, registry: AgentRegistry, gateway: ToolGateway, validator: EvidenceValidator, model: ModelClient) -> None:
        self.registry, self.gateway, self.validator, self.model = registry, gateway, validator, model

    def run(self, task: AgentTask, context: dict, evidence_ids: Set[str]) -> AgentResult:
        definition = self.registry.get(task.agent_role)
        payload = self.model.complete_json(task.agent_role, definition.prompt_version, context, AgentResult.model_json_schema())
        result = AgentResult.model_validate(payload)
        errors = self.validator.validate(result, evidence_ids)
        if errors:
            raise ValueError("; ".join(errors))
        return result


def default_agent_registry() -> AgentRegistry:
    common = {"evidence_get", "detection_lookup"}
    return AgentRegistry([
        AgentDefinition("coordinator", "1.0.0", {"chain_lookup", "source_health", "detection_lookup"}),
        AgentDefinition("host", "1.0.0", common | {"event_search", "entity_timeline", "session_lookup", "graph_neighbors"}),
        AgentDefinition("network", "1.0.0", common | {"event_search", "session_lookup", "graph_neighbors"}),
        AgentDefinition("correlation", "1.0.0", common | {"chain_lookup", "chain_validate", "graph_path", "graph_neighbors"}),
        AgentDefinition("attribution", "1.0.0", common | {"attack_lookup", "chain_lookup"}),
        AgentDefinition("report", "1.0.0", common | {"chain_lookup"}),
    ])
