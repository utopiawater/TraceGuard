from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.harness import default_agent_registry
from app.agents.harness import EvidenceValidator
from app.agents.service import InvestigationService
from app.agents.tools import build_tool_gateway
from app.bootstrap import build_pipeline
from app.attack.chain_builder import DeterministicChainBuilder
from app.contracts import AgentResult, AgentTask, AttackMapping, DetectionResult
from app.core.settings import Settings
from app.datasets import inspect_dataset, load_evaluation_ground_truth, load_raw_envelopes, write_dataset_run_report
from app.datasets.darpa_tc_e3 import DATASET_ID, DATASET_NAME
from app.graph import InMemoryGraphProjector
from app.knowledge import MappingFileProvider
from app.main import create_app
from app.normalizers.darpa_tc_e3 import DarpaTcE3CadetsAdapter
from app.repositories import SQLiteRepository


ROOT = Path(__file__).parents[2]
DATASET = ROOT / "datasets" / "darpa_tc_e3_cadets"
ATTACK = ROOT / "knowledge" / "attack" / "mappings.json"


def _settings(tmp_path):
    return Settings(data_dir=tmp_path, database_path=tmp_path / "darpa.db", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False, llm_base_url="", llm_api_key="", llm_model="")


def _event(raws, original_event_id):
    return next(item for item in raws if item.source_record_id == original_event_id)


def _task(task_id="task_dataset", role="host", tools=None):
    return AgentTask(
        task_id=task_id,
        case_id="case_dataset",
        agent_role=role,
        objective="inspect dataset",
        input_refs=[],
        allowed_tools=tools or ["event_search"],
        constraints={"max_steps": 10, "deadline_ms": 1000, "read_only": True},
        state="queued",
    )


def _detection(rule_id, technique_id, confidence, created_at, tactic_id="TA0004"):
    return DetectionResult(
        detection_id="det_%s_%s" % (rule_id.rsplit(".", 1)[-1], technique_id),
        run_id="run_chain_select",
        rule_id=rule_id,
        rule_version="1.0.0",
        title=rule_id,
        detector_type="rule",
        severity="high",
        confidence=confidence,
        event_ids=["evt_%s" % technique_id],
        entity_ids=["host_1"],
        evidence_ids=["evd_%s" % technique_id],
        reason="test detection",
        created_at=created_at,
        attack_mappings=[
            AttackMapping(
                technique_id=technique_id,
                tactic_ids=[tactic_id],
                mapping_rule_id="map_%s" % technique_id,
                attack_version="19.2",
                confidence=confidence,
            )
        ],
    )


def test_darpa_dataset_actual_counts_and_field_distribution():
    report = inspect_dataset(DATASET)
    assert report["dataset_id"] == DATASET_ID
    assert report["dataset_name"] == DATASET_NAME
    assert report["counts"] == {"process_events.json": 15441, "network_events.json": 765, "file_events.json": 4570}
    assert report["total_events"] == 20776
    assert report["unique_event_ids"] == 20776
    assert report["action_distribution"]["aue_fcntl"] == 15247
    assert report["event_type_distribution"]["recvfrom"] == 569


def test_darpa_reader_loads_three_files_without_exposing_ground_truth_labels():
    raws = load_raw_envelopes(DATASET)
    assert len(raws) == 20776
    assert {item.payload["dataset_file"] for item in raws} == {"process_events.json", "network_events.json", "file_events.json"}
    assert all(item.source.kind.value == "dataset" and item.source.dataset == DATASET_ID for item in raws)
    assert all("attack_label" not in item.payload and "selection_reason" not in item.payload for item in raws)


def test_darpa_normalizer_maps_process_network_and_file_samples_to_unified_schema():
    raws = load_raw_envelopes(DATASET)
    adapter = DarpaTcE3CadetsAdapter()
    process = adapter.normalize(_event(raws, "cadets:record:3587335"))[0]
    network = adapter.normalize(_event(raws, "cadets:record:3587177"))[0]
    file_event = adapter.normalize(_event(raws, "cadets:record:3600804"))[0]
    assert process.action == "memory.protect"
    assert process.actor.process and process.actor.process.attributes["subject_id"] == "11C64B2C-3DC3-11E8-A5CA-3FA3753A265A"
    assert network.action == "network.connect"
    assert network.network and network.network.dst.ip == "76.56.184.25" and network.network.dst.port == 80
    assert file_event.action == "process.execute"
    assert file_event.object.ref and file_event.object.ref.attributes["normalized_path"] == "/tmp/tmux-1002"
    for event in (process, network, file_event):
        assert event.model_dump()
        assert "attack_label" not in event.model_dump_json()
        assert "selection_reason" not in event.model_dump_json()


def test_unknown_darpa_action_is_preserved_with_mapping_warning():
    raw = load_raw_envelopes(DATASET)[0]
    modified = raw.model_copy(update={"payload": {**raw.payload, "action": "aue_not_real"}})
    event = DarpaTcE3CadetsAdapter().normalize(modified)[0]
    assert event.action == "dataset.unknown"
    assert event.provenance.mapping_warnings == ["unknown darpa action: aue_not_real"]


def test_ground_truth_loader_is_evaluation_only_and_agent_tools_do_not_expose_it(tmp_path):
    truth = load_evaluation_ground_truth(DATASET)
    assert len(truth["ioc_event_ids"]) == 776
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    result = build_pipeline(settings, repo, graph).run("run_gt_isolation", load_raw_envelopes(DATASET)[:8])
    gateway = build_tool_gateway(repo, graph, MappingFileProvider(ATTACK))
    payload = gateway.invoke(
        _task("task_gt"),
        default_agent_registry(),
        "event_search",
        {"run_id": result.run_id, "limit": 8},
    )
    assert "attack_label" not in str(payload)
    assert "selection_reason" not in str(payload)


def test_run_scoped_queries_keep_dataset_runs_isolated(tmp_path):
    raws = load_raw_envelopes(DATASET)
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    pipeline = build_pipeline(settings, repo, graph)
    first = pipeline.run("run_scope_a", raws[:3])
    second = pipeline.run("run_scope_b", raws[3:6])
    assert {event.event_id for event in repo.query_events(run_id=first.run_id, limit=10)} == {event.event_id for event in first.events}
    assert {event.event_id for event in repo.query_events(run_id=second.run_id, limit=10)} == {event.event_id for event in second.events}
    assert not ({event.event_id for event in first.events} & {event.event_id for event in second.events})


def test_agent_event_search_can_find_early_dataset_event_beyond_5000_rows(tmp_path):
    raws = load_raw_envelopes(DATASET)[:6001]
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    result = build_pipeline(settings, repo, graph).run("run_large_query", raws)
    gateway = build_tool_gateway(repo, graph, MappingFileProvider(ATTACK))
    payload = gateway.invoke(_task("task_large"), default_agent_registry(), "event_search", {"run_id": result.run_id, "text": "cadets:record:3587335", "limit": 3})
    assert payload["count"] == 1
    assert payload["events"][0]["extensions"]["dataset"]["original_event_id"] == "cadets:record:3587335"


def test_dataset_api_returns_real_run_report_from_data_dir(tmp_path):
    report = {
        "dataset_id": DATASET_ID,
        "dataset_name": DATASET_NAME,
        "source": "DARPA Transparent Computing E3",
        "scenario": "E3-CADETS-20180412-nginx",
        "run_id": "run_api_dataset",
        "status": "completed",
        "records": 20776,
        "normalized_records": 20776,
        "failed_records": 0,
        "mapping_rate": 1.0,
        "detection_count": 1,
        "technique_ids": ["T1046"],
        "technique_count": 1,
        "chain_count": 1,
        "ioc_coverage": {"covered": 1, "total": 776, "rate": 0.001289},
        "ioc_coverage_analysis": {"uncovered_ioc_events": 775},
        "stage_coverage": {"covered": 1, "total": 4, "rate": 0.25, "stages": ["execution"]},
        "evidence_backtrace_rate": 1.0,
        "runtime_seconds": 1.2,
        "precision": None,
        "recall": None,
        "f1": None,
        "f1_reason": "no complete labels",
    }
    write_dataset_run_report(report, tmp_path)
    client = TestClient(create_app(_settings(tmp_path)))
    payload = client.get("/api/datasets").json()["data"]
    row = next(item for item in payload if item["run_id"] == "run_api_dataset")
    assert row["dataset_id"] == DATASET_ID
    assert row["records"] == 20776
    assert row["ioc_coverage_analysis"]["uncovered_ioc_events"] == 775
    assert row["f1"] is None


def test_attack_api_uses_knowledge_name_for_t1046(tmp_path):
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    repo.put_detections([
        _detection(
            "det.network.service_scanning",
            "T1046",
            0.82,
            datetime(2018, 4, 12, 18, 20, tzinfo=timezone.utc),
            "TA0007",
        )
    ])
    client = TestClient(create_app(settings))
    payload = client.get("/api/attack").json()["data"]
    assert payload[0]["technique_id"] == "T1046"
    assert payload[0]["technique_name"] == "Network Service Scanning"


def test_dataset_replay_duplicate_run_is_explicit(tmp_path):
    raws = load_raw_envelopes(DATASET)[:5]
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    pipeline = build_pipeline(settings, repo, graph)
    first = pipeline.run("run_duplicate", raws)
    second = pipeline.run("run_duplicate", raws)
    assert first.accepted_raw == 5
    assert second.accepted_raw == 0
    assert repo.counts()["normalized_events"] == 5


def test_chain_builder_prefers_stronger_stage_representative_over_first_seen():
    first_memory = _detection(
        "det.host.memory_tampering",
        "T1055",
        0.84,
        datetime(2018, 4, 12, 18, 0, 23, tzinfo=timezone.utc),
    )
    later_privilege = _detection(
        "det.host.privilege_escalation",
        "T1068",
        0.9,
        datetime(2018, 4, 12, 18, 10, 0, tzinfo=timezone.utc),
    )
    chain = DeterministicChainBuilder().build("run_chain_select", [first_memory, later_privilege])[0]
    assert len(chain.steps) == 1
    assert chain.steps[0].stage == "privilege_escalation"
    assert chain.steps[0].technique_id == "T1068"
    assert chain.steps[0].detection_ids == [later_privilege.detection_id]


def test_quick_fallback_aggregates_detection_findings_and_keeps_valid_evidence():
    detections = [
        _detection("det.host.sensitive_file_collection", "T1005", 0.88, datetime(2018, 4, 12, 18, index, tzinfo=timezone.utc))
        for index in range(3)
    ]
    detections.append(_detection("det.host.privilege_escalation", "T1068", 0.9, datetime(2018, 4, 12, 18, 10, tzinfo=timezone.utc)))
    findings = InvestigationService._aggregate_detection_findings(detections)
    assert len(findings) == 2
    assert any("3 条同类检测" in finding.claim for finding in findings)
    evidence_ids = {evidence_id for detection in detections for evidence_id in detection.evidence_ids}
    result = AgentResult.model_validate({
        "result_id": "agent_result_aggregate",
        "task_id": "task_aggregate",
        "status": "succeeded",
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "tool_calls": [],
        "output_refs": [],
        "errors": [],
        "model_info": {"provider": "deterministic", "model": "fallback-v1", "prompt_version": "1.0.0"},
    })
    assert EvidenceValidator().validate(result, evidence_ids) == []
