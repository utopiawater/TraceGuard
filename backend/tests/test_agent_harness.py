from pathlib import Path

import pytest
from pydantic import ValidationError

from app.agents.harness import EvidenceValidator, Orchestrator, Tool, ToolGateway, default_agent_registry
from app.agents.service import InvestigationService
from app.agents.tools import build_tool_gateway
from app.bootstrap import build_pipeline
from app.contracts import AgentResult, AgentTask
from app.core.settings import Settings
from app.graph import InMemoryGraphProjector
from app.knowledge import MappingFileProvider
from app.repositories import SQLiteRepository
from app.scenarios import load_scenario


SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain"
ATTACK = Path(__file__).parents[2] / "knowledge" / "attack" / "mappings.json"


def task(role="host", tools=None):
    return AgentTask(task_id="task_1", case_id="case_1", agent_role=role, objective="inspect", input_refs=[], allowed_tools=tools or ["event_search"], constraints={"max_steps": 3, "deadline_ms": 1000, "read_only": True}, state="queued")


def valid_result(evidence_ids=None):
    return AgentResult.model_validate({
        "result_id": "result_1", "task_id": "task_1", "status": "succeeded",
        "findings": [{"claim": "verified", "confidence": .8, "evidence_ids": evidence_ids or ["evidence_1"], "alternatives": []}],
        "tool_calls": [], "output_refs": [], "errors": [],
        "model_info": {"provider": "fake", "model": "fake-1", "prompt_version": "1.0.0"},
    })


def seeded(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "agent.db", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False, llm_base_url="", llm_api_key="", llm_model="")
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    result = build_pipeline(settings, repo, graph).run("run_agent_test", load_scenario(SCENARIO))
    return settings, repo, graph, result.chains[0]


def test_tool_gateway_enforces_role_task_and_read_only_permissions():
    registry = default_agent_registry()
    gateway = ToolGateway([Tool("event_search", lambda args: {"refs": []}), Tool("unsafe", lambda args: {}, read_only=False)])
    current = task()
    assert gateway.invoke(current, registry, "event_search", {}) == {"refs": []}
    with pytest.raises(PermissionError):
        gateway.invoke(current, registry, "attack_lookup", {})
    with pytest.raises(PermissionError):
        gateway.invoke(current.model_copy(update={"allowed_tools": ["unsafe"]}), registry, "unsafe", {})
    assert [item.status for item in gateway.audit_for(current.task_id)] == ["succeeded", "denied", "denied"]


def test_tool_argument_limits_and_unknown_attack_are_rejected(tmp_path):
    _, repo, graph, _ = seeded(tmp_path)
    gateway = build_tool_gateway(repo, graph, MappingFileProvider(ATTACK))
    host = task("host", ["event_search"])
    with pytest.raises(ValidationError):
        gateway.invoke(host, default_agent_registry(), "event_search", {"limit": 201})
    attribution = task("attribution", ["attack_lookup"])
    with pytest.raises(ValueError, match="does not exist"):
        gateway.invoke(attribution, default_agent_registry(), "attack_lookup", {"technique_ids": ["T9999.999"]})


def test_evidence_validator_rejects_empty_and_nonexistent_evidence():
    validator = EvidenceValidator()
    assert "missing evidence" in validator.validate(valid_result(["missing"]), {"evidence_1"})[0]
    payload = valid_result().model_dump()
    payload["findings"][0]["evidence_ids"] = []
    assert "has no evidence" in validator.validate(AgentResult.model_validate(payload), {"evidence_1"})[0]


class FakeModel:
    def __init__(self):
        self.schemas = []

    def complete_json(self, role, prompt_version, payload, schema):
        self.schemas.append(schema)
        return valid_result().model_dump(mode="json")


def test_agent_result_json_schema_is_enforced():
    model = FakeModel()
    orchestrator = Orchestrator(default_agent_registry(), ToolGateway([]), EvidenceValidator(), model)
    result = orchestrator.run(task(), {"verified": True}, {"evidence_1"})
    assert result.status == "succeeded"
    assert model.schemas[0]["additionalProperties"] is False
    invalid = valid_result().model_dump()
    invalid["unexpected"] = True
    with pytest.raises(ValidationError):
        AgentResult.model_validate(invalid)


class EchoDraftModel:
    configured = True
    def complete_json(self, role, prompt_version, payload, schema):
        return payload["draft"]


class FailingModel:
    configured = True
    def complete_json(self, role, prompt_version, payload, schema):
        raise RuntimeError("model offline")


def test_coordinator_runs_parallel_specialists_and_persists_full_flow(tmp_path):
    settings, repo, graph, chain = seeded(tmp_path)
    service = InvestigationService(repo, graph, settings)
    service.model = EchoDraftModel()
    summary = service.investigate(chain.chain_id)
    records = [item for item in repo.list_agent_records(100) if item["task"]["case_id"] == summary["case_id"]]
    assert summary["status"] == "succeeded"
    assert {item["task"]["agent_role"] for item in records} == {"coordinator", "host", "network", "correlation", "attribution", "report"}
    assert all(item["result"]["result"]["findings"] for item in records)
    assert all(finding["evidence_ids"] for item in records for finding in item["result"]["result"]["findings"])
    by_role = {item["task"]["agent_role"]: item for item in records}
    assert {call["tool"] for call in by_role["host"]["result"]["result"]["tool_calls"]} >= {"event_search", "entity_timeline", "detection_lookup", "evidence_get"}
    assert {call["tool"] for call in by_role["network"]["result"]["result"]["tool_calls"]} >= {"event_search", "session_lookup", "detection_lookup", "evidence_get"}
    assert by_role["correlation"]["result"]["artifact"]["chain_valid"] is True
    assert len(repo.list_reports()) == 2


def test_model_failure_uses_deterministic_fallback_without_aborting(tmp_path):
    settings, repo, graph, chain = seeded(tmp_path)
    service = InvestigationService(repo, graph, settings)
    service.model = FailingModel()
    summary = service.investigate(chain.chain_id)
    records = [item for item in repo.list_agent_records(100) if item["task"]["case_id"] == summary["case_id"]]
    assert summary["status"] == "succeeded"
    assert all(item["result"]["runtime"]["fallback"] for item in records)
    assert all(item["result"]["result"]["model_info"]["model"] == "fallback-v1" for item in records)
    assert all(any(error["code"] == "model_fallback" for error in item["result"]["result"]["errors"]) for item in records)
