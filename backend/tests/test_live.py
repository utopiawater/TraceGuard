from pathlib import Path

from fastapi.testclient import TestClient

from app.core.settings import Settings
from app.graph import InMemoryGraphProjector
from app.live import LiveRunService
from app.main import create_app
from app.repositories import SQLiteRepository
from app.worker import Worker


SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain"


def _settings(tmp_path, **overrides):
    values = {
        "data_dir": tmp_path,
        "database_path": tmp_path / "live.db",
        "raw_archive_dir": tmp_path / "raw",
        "report_dir": tmp_path / "reports",
        "neo4j_enabled": False,
        "live_micro_batch_size": 4,
    }
    values.update(overrides)
    return Settings(**values)


def test_replay_live_run_updates_single_run_incrementally(tmp_path):
    settings = _settings(tmp_path)
    repo = SQLiteRepository(settings.database_path)
    service = LiveRunService(settings, repo, InMemoryGraphProjector())

    run = service.start(str(SCENARIO))
    run_id = run["run_id"]
    first = service.poll_once(run_id)
    first_counts = repo.counts(run_id)
    second = service.poll_once(run_id)
    second_counts = repo.counts(run_id)

    assert first == 4
    assert second == 4
    assert second_counts["raw_events"] > first_counts["raw_events"]
    assert second_counts["normalized_events"] > first_counts["normalized_events"]
    assert second_counts["detections"] >= first_counts["detections"]
    assert repo.get_run(run_id)["mode"] == "live"
    assert repo.get_run(run_id)["status"] == "running"
    assert repo.counts(run_id)["attack_chains"] >= 1

    stopped = service.stop(run_id)
    assert stopped["status"] == "completed"


def test_worker_uses_checkpoint_after_restart_without_duplicate_replay(tmp_path):
    settings = _settings(tmp_path, live_micro_batch_size=50)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    run_id = LiveRunService(settings, repo, graph).start(str(SCENARIO))["run_id"]

    assert Worker(repo, settings, graph).run_once() > 0
    counts = repo.counts(run_id)
    assert Worker(repo, settings, graph).run_once() == 0
    assert repo.counts(run_id) == counts


def test_malformed_wazuh_line_and_offline_source_do_not_fail_live_run(tmp_path):
    wazuh = tmp_path / "wazuh-alerts.jsonl"
    wazuh.write_text("{bad json}\n", encoding="utf-8")
    missing = tmp_path / "missing-alerts.jsonl"
    settings = _settings(tmp_path, wazuh_jsonl_paths="%s;%s" % (wazuh, missing), live_micro_batch_size=10)
    repo = SQLiteRepository(settings.database_path)
    service = LiveRunService(settings, repo, InMemoryGraphProjector())
    run_id = service.start()["run_id"]

    assert service.poll_once(run_id) == 1
    status = service.status(run_id)
    assert status["status"] == "running"
    assert status["counts"]["raw_events"] == 1
    assert status["counts"]["normalized_events"] == 0
    assert status["counts"]["evidence"] == 1
    assert repo.counts()["dead_letters"] == 1
    assert any(source["status"] == "online" for source in status["sources"])


def test_http_live_ingest_enters_existing_live_pipeline(tmp_path):
    app = create_app(_settings(tmp_path))
    client = TestClient(app)
    run_id = client.post("/api/v1/live/start", json={}).json()["data"]["run_id"]
    payload = {
        "run_id": run_id,
        "timestamp": "2026-09-07T08:00:00Z",
        "source_host": "win-client-01",
        "source_type": "wazuh",
        "raw_message": {
            "timestamp": "2026-09-07T08:00:00Z",
            "agent": {"id": "007", "name": "win-client-01"},
            "rule": {"level": 8, "description": "successful logon"},
            "data": {"win": {"system": {"eventID": "4624", "computer": "win-client-01"}, "eventdata": {"TargetUserName": "student", "TargetLogonId": "0x1", "LogonType": "3", "IpAddress": "10.0.0.5"}}},
        },
    }

    posted = client.post("/api/ingest/logs/live", json=payload)
    assert posted.status_code == 200
    status = client.get("/api/v1/live/status?run_id=%s" % run_id).json()["data"]
    assert status["counts"]["raw_events"] == 1
    assert status["counts"]["normalized_events"] == 1
    assert client.get("/api/events?run_id=%s" % run_id).json()["data"][0]["source"]["kind"] == "wazuh"
