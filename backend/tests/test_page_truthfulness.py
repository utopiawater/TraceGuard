from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.contracts import (
    AgentResult,
    AgentTask,
    AttackChain,
    AttackMapping,
    ChainStep,
    DetectionResult,
    EntityRef,
    Evidence,
    GraphEntity,
    GraphRelation,
    RawEventEnvelope,
    SourceDescriptor,
    TimeContext,
    UnifiedSecurityEvent,
)
from app.contracts.common import SourceKind
from app.contracts.agents import ModelInfo
from app.contracts.events import EventProvenance
from app.core.settings import Settings
from app.main import create_app
from app.repositories import SQLiteRepository


def _settings(tmp_path):
    return Settings(data_dir=tmp_path, database_path=tmp_path / "truth.db", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False, llm_base_url="", llm_api_key="", llm_model="")


def _raw(index: int) -> RawEventEnvelope:
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    source = SourceDescriptor(kind=SourceKind.dataset, product="test", dataset="synthetic", sensor_id="sensor", source_record_id=str(index))
    return RawEventEnvelope(raw_id=f"raw_{index}", source=source, source_record_id=str(index), event_time_raw=now.isoformat(), observed_time=now, ingested_time=now, payload_format="json", payload={"index": index}, raw_ref=f"test://{index}", raw_sha256=f"sha_{index}")


def _event(index: int, run_id: str, action: str = "process.start") -> UnifiedSecurityEvent:
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=index)
    source = SourceDescriptor(kind=SourceKind.dataset, product="test", dataset="synthetic", sensor_id="sensor", source_record_id=str(index))
    host = EntityRef(entity_type="host", entity_id=f"host_{run_id}", display_name=run_id, identity_quality="derived")
    return UnifiedSecurityEvent(
        event_id=f"evt_{run_id}_{index}",
        event_time=now,
        observed_time=now,
        ingested_time=now,
        time=TimeContext(original=now.isoformat(), quality="synced"),
        source=source,
        host=host,
        action=action,
        event_type="synthetic",
        outcome="success",
        severity="informational",
        message=f"event {index}",
        provenance=EventProvenance(raw_id=f"raw_{index}", raw_ref=f"test://{index}", raw_sha256=f"sha_{index}", parser_name="test", parser_version="1"),
    )


def _evidence(index: int, run_id: str) -> Evidence:
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=index)
    return Evidence(evidence_id=f"evd_{run_id}_{index}", kind="normalized_event", source_ref=f"test://{index}", event_ids=[f"evt_{run_id}_{index}"], entity_ids=[f"host_{run_id}"], observed_at=now, collected_at=now, producer="test", producer_version="1", reliability="direct")


def _detection(index: int, run_id: str) -> DetectionResult:
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=index)
    return DetectionResult(detection_id=f"det_{run_id}_{index}", run_id=run_id, rule_id="det.test", rule_version="1", title=f"detection {index}", detector_type="rule", severity="medium", confidence=0.5, event_ids=[f"evt_{run_id}_{index}"], entity_ids=[f"host_{run_id}"], evidence_ids=[f"evd_{run_id}_{index}"], reason="test", created_at=now)


def _chain(run_id: str, index: int) -> AttackChain:
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=index)
    mapping = AttackMapping(technique_id="T1059", tactic_ids=["TA0002"], mapping_rule_id="test", attack_version="19.2", confidence=0.8)
    step = ChainStep(step_id=f"step_{run_id}_{index}", stage="execution", tactic_id="TA0002", technique_id="T1059", event_ids=[f"evt_{run_id}_{index}"], detection_ids=[f"det_{run_id}_{index}"], entity_ids=[f"host_{run_id}", "T1059"], start_time=now, end_time=now, score=0.7, evidence_ids=[f"evd_{run_id}_{index}"], explanation="test")
    detection = _detection(index, run_id).model_copy(update={"attack_mappings": [mapping]})
    return AttackChain(chain_id=f"chain_{run_id}_{index}", run_id=run_id, title=f"chain {run_id}", start_time=now, end_time=now, steps=[step], entity_ids=[f"host_{run_id}", "T1059"], detection_ids=[detection.detection_id], technique_ids=["T1059"], score=0.7, completeness=0.2, evidence_ids=[f"evd_{run_id}_{index}"], algorithm_version="test")


def _seed(repo: SQLiteRepository, run_id: str, count: int) -> None:
    raws = [_raw(index) for index in range(count)]
    for raw in raws:
        repo.put_raw(raw)
    repo.start_run(run_id, "replay", {"source": f"source-{run_id}", "raw_ids": [raw.raw_id for raw in raws]}, {"test": "1"})
    repo.append_events(run_id, [_event(index, run_id, "network.flow" if index % 10 == 0 else "process.start") for index in range(count)])
    repo.put_evidence(run_id, [_evidence(index, run_id) for index in range(count)])
    repo.put_detections([_detection(index, run_id) for index in range(count)])
    repo.put_chains([_chain(run_id, 0)])
    repo.complete_run(run_id)


def test_events_and_detections_are_paginated_latest_first_and_run_scoped(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings)
    _seed(app.state.repository, "run_A", 130)
    _seed(app.state.repository, "run_B", 20)
    client = TestClient(app)

    events = client.get("/api/events?run_id=run_A&limit=25").json()
    assert events["meta"]["total"] == 130
    assert len(events["data"]) == 25
    assert events["data"][0]["event_id"] == "evt_run_A_129"
    assert all(item["event_id"].startswith("evt_run_A_") for item in events["data"])
    page_two = client.get("/api/events?run_id=run_A&limit=25&offset=25").json()["data"]
    assert page_two[0]["event_id"] == "evt_run_A_104"

    detections = client.get("/api/detections?run_id=run_B&limit=10").json()
    assert detections["meta"]["total"] == 20
    assert detections["data"][0]["detection_id"] == "det_run_B_19"
    assert all(item["run_id"] == "run_B" for item in detections["data"])

    alerts = client.get("/api/alerts?run_id=run_B&limit=5").json()
    assert alerts["meta"]["total"] == 20
    assert len(alerts["data"]) == 5
    assert alerts["data"][0]["detection_id"] == "det_run_B_19"
    assert all(item["detection_id"].startswith("det_run_B_") for item in alerts["data"])


def test_run_registry_includes_sqlite_runs_not_only_analysis_task_files(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings)
    _seed(app.state.repository, "run_sqlite_only", 1)
    payload = TestClient(app).get("/api/v1/analysis/tasks").json()["data"]
    row = next(item for item in payload if item["task_id"] == "run_sqlite_only")
    assert row["source"] == "sqlite_runs"
    assert row["upload"]["filename"] == "source-run_sqlite_only"


def test_chain_graph_and_evidence_detail_are_exact_not_global_limited(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings)
    _seed(app.state.repository, "run_graph", 1)
    app.state.graph.entities.update({f"noise_{index}": GraphEntity(entity_id=f"noise_{index}", entity_type="host", display_name=f"noise {index}") for index in range(120)})
    app.state.graph.entities["host_run_graph"] = GraphEntity(entity_id="host_run_graph", entity_type="host", display_name="run_graph")
    app.state.graph.entities["T1059"] = GraphEntity(entity_id="T1059", entity_type="technique", display_name="T1059")
    app.state.graph.relations["rel_chain"] = GraphRelation(relation_id="rel_chain", relation_type="USED_TECHNIQUE", source_entity_id="host_run_graph", target_entity_id="T1059", confidence=1.0, evidence_ids=["evd_run_graph_0"])
    client = TestClient(app)

    graph = client.get("/api/graph?chain_id=chain_run_graph_0").json()["data"]
    assert {node["entity_id"] for node in graph["nodes"]} == {"host_run_graph", "T1059"}
    assert [edge["relation_id"] for edge in graph["edges"]] == ["rel_chain"]
    evidence = client.get("/api/evidence/evd_run_graph_0").json()["data"]
    assert evidence["event_ids"] == ["evt_run_graph_0"]


def test_search_agent_results_are_run_scoped(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings)
    _seed(app.state.repository, "run_agent_a", 1)
    _seed(app.state.repository, "run_agent_b", 1)
    for run_id in ("run_agent_a", "run_agent_b"):
        task = AgentTask(task_id=f"task_{run_id}", case_id=f"case_{run_id}", agent_role="coordinator", objective="needle-agent", state="succeeded")
        app.state.repository.put_agent_task(task, {"chain_id": f"chain_{run_id}_0"})
        app.state.repository.put_agent_result(AgentResult(result_id=f"result_{run_id}", task_id=task.task_id, status="succeeded", model_info=ModelInfo(provider="deterministic", model="fallback", prompt_version="test")), runtime={"chain_id": f"chain_{run_id}_0"})
    payload = TestClient(app).get("/api/search?q=needle-agent&run_id=run_agent_b").json()["data"]
    assert payload
    assert {item["type"] for item in payload} == {"agent"}
    assert {item["run_id"] for item in payload} == {"run_agent_b"}
