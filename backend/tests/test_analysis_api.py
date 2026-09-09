from pathlib import Path
import zipfile

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
    assert "PCAP 已接收" in payload["meta"]["warnings"][0]
    task = payload["data"]
    started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
    assert started.status_code == 200
    assert started.json()["data"]["status"] == "completed"
    assert started.json()["data"]["result"]["normalized_events"] == 0
