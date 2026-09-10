from pathlib import Path
import json
import zipfile
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.settings import Settings
from app.main import create_app


def test_online_analysis_upload_nested_zip_and_task_isolation(tmp_path):
    source = Path(__file__).parents[1] / "fixtures" / "scenarios" / "powershell_cross_source" / "sysmon_1_process_create.xml"
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.write(source, "nested/sysmon_1_process_create.xml")

    app = create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False))
    client = TestClient(app)

    counts = []
    task_ids = []
    for _ in range(2):
        uploaded = client.post("/api/v1/analysis/upload", files={"file": ("sample.zip", archive.read_bytes(), "application/zip")})
        assert uploaded.status_code == 200
        task = uploaded.json()["data"]
        task_ids.append(task["task_id"])
        assert [item["kind"] for item in task["identification"]["found"]] == ["Sysmon"]

        started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
        assert started.status_code == 200
        result = started.json()["data"]["result"]
        counts.append(result["normalized_events"])
        scoped = client.get("/api/events?run_id=%s" % task["task_id"]).json()["data"]
        assert len(scoped) == result["normalized_events"]

    assert task_ids[0] != task_ids[1]
    assert counts == [1, 1]


def test_online_analysis_pcap_without_parser_is_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr("app.analysis.service.shutil.which", lambda _: None)
    app = create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False))
    client = TestClient(app)
    uploaded = client.post("/api/v1/analysis/upload", files={"file": ("flow.pcap", b"\xd4\xc3\xb2\xa1", "application/octet-stream")})
    assert uploaded.status_code == 200
    payload = uploaded.json()
    assert "Python 内置 flow 聚合 fallback" in payload["meta"]["warnings"][0]
    task = payload["data"]
    started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
    assert started.status_code == 200
    assert started.json()["data"]["status"] == "completed"
    assert started.json()["data"]["result"]["normalized_events"] == 0


def test_analysis_manifest_policy_scopes_time_asset_aliases_and_excludes_gt(tmp_path):
    archive = tmp_path / "manifested.zip"
    manifest = {
        "default_timezone": "+08:00",
        "asset_aliases": {"remote/web": "N4-Web", "web": "N4-Web"},
        "sensitive_path_patterns": ["/data/secret/**"],
        "attack_steps": ["ground truth must remain evaluation-only"],
        "expected_technique": ["T0000"],
    }
    auditd = 'type=SYSCALL msg=audit(1788939734.337:180): arch=c000003e syscall=59 success=yes pid=2711 ppid=1 uid=0 euid=0 comm="bash" exe="/bin/bash" items=0'
    sample = [{"timestamp": "2026-09-09T15:56:22", "host": "web", "process": "bash", "action": "process.start", "event_id": "sample-1"}]
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("manifest.json", json.dumps(manifest))
        handle.writestr("remote/web/auditd.log", auditd)
        handle.writestr("events.json", json.dumps(sample))

    app = create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False))
    client = TestClient(app)

    uploaded = client.post("/api/v1/analysis/upload", files={"file": ("manifested.zip", archive.read_bytes(), "application/zip")})
    assert uploaded.status_code == 200
    task = uploaded.json()["data"]
    assert task["policy"]["default_timezone"] == "+08:00"
    assert task["policy"]["asset_aliases"]["remote/web"] == "N4-Web"
    assert "attack_steps" not in task["policy"]
    assert "expected_technique" not in task["policy"]

    started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
    assert started.status_code == 200
    assert started.json()["data"]["stages"][-1] == {"key": "completed", "label": "基础分析完成", "status": "completed"}
    events = client.get("/api/events?run_id=%s&limit=20" % task["task_id"]).json()["data"]
    assert {event["host"]["display_name"] for event in events if event.get("host")} == {"n4-web"}
    sample_event = next(event for event in events if event["source"]["dataset"] == "sample_attack_dataset")
    assert sample_event["event_time"] == "2026-09-09T07:56:22Z"


def test_analysis_start_persists_pipeline_progress_stages(tmp_path, monkeypatch):
    source = Path(__file__).parents[1] / "fixtures" / "scenarios" / "powershell_cross_source" / "sysmon_1_process_create.xml"
    archive = tmp_path / "sysmon.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.write(source, "sysmon_1_process_create.xml")
    app = create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False))
    client = TestClient(app)
    uploaded = client.post("/api/v1/analysis/upload", files={"file": ("sysmon.zip", archive.read_bytes(), "application/zip")})
    assert uploaded.status_code == 200
    task_id = uploaded.json()["data"]["task_id"]
    observed = []

    class FakePipeline:
        def run(self, run_id, raws, mode="replay", progress=None):
            assert run_id == task_id
            assert progress is not None
            for stage in ("detections", "attack", "correlated", "chains", "ready_for_agent"):
                progress(stage)
                task = json.loads((tmp_path / "analysis_tasks" / task_id / "task.json").read_text(encoding="utf-8"))
                observed.append(task["current_stage"])
                assert task["stages"][next(index for index, item in enumerate(task["stages"]) if item["key"] == stage)]["status"] == "running"
            return SimpleNamespace(accepted_raw=len(raws), events=[], detections=[], graph_entities=[], chains=[])

    monkeypatch.setattr("app.analysis.service.build_pipeline", lambda settings, repository, graph: FakePipeline())
    started = client.post("/api/v1/analysis/tasks/%s/start" % task_id)
    assert started.status_code == 200
    assert observed == ["detections", "attack", "correlated", "chains", "ready_for_agent"]
    assert started.json()["data"]["current_stage"] == "completed"
