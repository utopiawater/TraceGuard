from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from .base import ContractModel


class AgentConstraints(ContractModel):
    max_steps: int = Field(default=8, ge=1, le=50)
    deadline_ms: int = Field(default=60000, ge=1000)
    read_only: bool = True


class AgentTask(ContractModel):
    task_id: str
    case_id: str
    agent_role: Literal["coordinator", "host", "network", "correlation", "attribution", "report"]
    objective: str
    input_refs: List[str] = Field(default_factory=list)
    allowed_tools: List[str] = Field(default_factory=list)
    constraints: AgentConstraints = Field(default_factory=AgentConstraints)
    parent_task_id: Optional[str] = None
    state: Literal["queued", "running", "succeeded", "failed", "cancelled"] = "queued"


class AgentFinding(ContractModel):
    claim: str
    confidence: float = Field(ge=0, le=1)
    evidence_ids: List[str]
    alternatives: List[str] = Field(default_factory=list)


class ToolCallSummary(ContractModel):
    tool: str
    input_summary: Dict[str, Any] = Field(default_factory=dict)
    output_refs: List[str] = Field(default_factory=list)
    status: Literal["succeeded", "failed", "denied"]


class StructuredError(ContractModel):
    code: str
    message: str
    retryable: bool = False


class ModelInfo(ContractModel):
    provider: str
    model: str
    prompt_version: str


class AgentResult(ContractModel):
    result_id: str
    task_id: str
    status: Literal["succeeded", "partial", "failed"]
    findings: List[AgentFinding] = Field(default_factory=list)
    tool_calls: List[ToolCallSummary] = Field(default_factory=list)
    output_refs: List[str] = Field(default_factory=list)
    errors: List[StructuredError] = Field(default_factory=list)
    model_info: ModelInfo
