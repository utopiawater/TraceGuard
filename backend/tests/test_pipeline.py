from pathlib import Path

from app.bootstrap import build_pipeline
from app.core.settings import Settings
from app.graph import InMemoryGraphProjector
from app.repositories import SQLiteRepository
from app.scenarios import load_scenario


SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "powershell_cross_source"


def test_cross_source_attack_chain_and_replay_idempotency(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "test.db", raw_archive_dir=tmp_path / "raw")
    repository = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    pipeline = build_pipeline(settings, repository, graph)
    raws = load_scenario(SCENARIO)

    result = pipeline.run("run_integration_001", raws)
    assert result.accepted_raw == 4
    assert len(result.events) == 4
    assert len(result.sessions) == 3
    assert [item.rule_id for item in result.detections] == [
        "det.auth.remote_interactive_logon", "det.host.suspicious_powershell", "det.network.cross_source_interpreter_connection"
    ]
    assert len(result.chains) == 1
    assert result.chains[0].technique_ids == ["T1059.001", "T1071.001"]
    assert all(step.evidence_ids for step in result.chains[0].steps)
    assert {"SPAWNED", "INITIATED", "FROM", "TO", "USED_TECHNIQUE"}.issubset({item.relation_type for item in result.graph_relations})

    before = repository.counts()
    replay = pipeline.run("run_integration_001", raws)
    assert replay.accepted_raw == 0
    assert repository.counts() == before


def test_full_multisource_chain_and_explainable_covert_channels(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "full.db", raw_archive_dir=tmp_path / "raw", neo4j_enabled=False)
    graph = InMemoryGraphProjector()
    result = build_pipeline(settings, SQLiteRepository(settings.database_path), graph).run(
        "run_full_multisource_001", load_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain")
    )
    by_rule = {item.rule_id: item for item in result.detections}
    for rule_id in ("det.network.dns_tunnel", "det.network.http_covert_channel", "det.network.icmp_tunnel"):
        detection = by_rule[rule_id]
        assert detection.feature_values
        assert detection.reason
        assert detection.confidence >= 0.65
        assert detection.evidence_ids
        assert detection.attack_mappings
    assert len(result.chains) == 1
    stages = [step.stage for step in result.chains[0].steps]
    assert stages == ["initial_access", "execution", "command_and_control", "lateral_movement", "privilege_escalation", "collection", "exfiltration"]
    assert result.chains[0].completeness == 1.0
    assert all(step.event_ids and step.detection_ids and step.entity_ids and step.evidence_ids and step.technique_id for step in result.chains[0].steps)
    assert {"ACCESSED", "CREATED", "MODIFIED", "DELETED", "COMMUNICATED_WITH", "CORROBORATES"}.issubset({item.relation_type for item in result.graph_relations})
