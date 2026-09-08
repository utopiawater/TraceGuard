from pathlib import Path

from fastapi.testclient import TestClient

from app.collectors import LinuxAuditCollector, ReplayCollector, WindowsEventCollector, ZeekCollector
from app.core.settings import Settings
from app.main import create_app
from app.normalizers.auditd import AuditdAdapter
from app.normalizers.sysmon import SysmonAdapter
from app.normalizers.windows_security import WindowsSecurityAdapter
from app.normalizers.zeek import ZeekAdapter


ROOT = Path(__file__).parents[1]
PROJECT_ROOT = ROOT.parent
FIXTURES = ROOT / "fixtures" / "collectors"


def test_collectors_emit_raw_event_envelopes():
    windows = WindowsEventCollector(FIXTURES / "windows_events.json").collect()
    auditd = LinuxAuditCollector(FIXTURES / "audit.log").collect()
    zeek = ZeekCollector(FIXTURES / "zeek").collect()
    replay = ReplayCollector(PROJECT_ROOT / "datasets" / "sample_attack_dataset.json").collect()

    assert len(windows) == 5
    assert len(auditd) == 3
    assert len(zeek) == 3
    assert len(replay) == 2
    assert {item.source.kind.value for item in windows} == {"windows_security", "sysmon"}
    assert all(item.raw_id and item.raw_sha256 and item.observed_time for item in windows + auditd + zeek + replay)


def test_collectors_feed_existing_normalizers():
    windows = WindowsEventCollector(FIXTURES / "windows_events.json").collect()
    security_events = [event for raw in windows if WindowsSecurityAdapter().supports(raw) for event in WindowsSecurityAdapter().normalize(raw)]
    sysmon_events = [event for raw in windows if SysmonAdapter().supports(raw) for event in SysmonAdapter().normalize(raw)]
    audit_events = [event for raw in LinuxAuditCollector(FIXTURES / "audit.log").collect() for event in AuditdAdapter().normalize(raw)]
    zeek_events = [event for raw in ZeekCollector(FIXTURES / "zeek").collect() for event in ZeekAdapter().normalize(raw)]

    assert {event.action for event in security_events} >= {"auth.logon"}
    assert {event.action for event in sysmon_events} >= {"process.start", "network.connect"}
    assert {event.action for event in audit_events} >= {"process.start", "file.read", "network.connect"}
    assert {event.action for event in zeek_events} >= {"network.flow", "dns.query", "http.request"}


def test_collectors_status_endpoint(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "collectors.db", raw_archive_dir=tmp_path / "raw")
    client = TestClient(create_app(settings))
    response = client.get("/api/collectors/status")

    assert response.status_code == 200
    statuses = response.json()["data"]
    assert {item["name"] for item in statuses} == {"windows_event", "linux_audit", "zeek", "replay"}
    assert all(item["status"] == "ok" for item in statuses)
    assert all(item["event_count"] > 0 for item in statuses)
