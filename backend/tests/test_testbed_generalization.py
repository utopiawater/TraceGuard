import json
import struct
import subprocess
import zipfile
from datetime import timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.analysis.service import AnalysisTaskService
from app.bootstrap import build_pipeline
from app.collectors.envelope import envelope_from_payload
from app.contracts import Evidence, RawEventEnvelope, SourceDescriptor
from app.core.settings import Settings
from app.core.time import parse_timestamp, utc_now
from app.detection.rules import FlowNetworkServiceScanningRule, HttpC2CandidateRule, PrivilegeEscalationRule, SensitiveFileCollectionRule, ServiceProcessExternalConnectionRule
from app.graph import InMemoryGraphProjector
from app.main import create_app
from app.normalizers import ApplicationWebAdapter, AuditdAdapter, NormalizerRegistry, WindowsSecurityAdapter, ZeekAdapter
from app.repositories import SQLiteRepository


def _raw(source_kind: str, dataset: str, payload, event_time) -> RawEventEnvelope:
    source = SourceDescriptor(kind=source_kind, product=source_kind, dataset=dataset, sensor_id="sensor-1", host_hint="host-1", source_record_id=str(event_time))
    return envelope_from_payload(source, payload, "json" if isinstance(payload, dict) else "text", event_time, "test://raw", parse_timestamp(event_time))


def _evidence(events):
    return [
        Evidence(
            evidence_id="evd_%s" % event.event_id,
            kind="normalized_event",
            source_ref=event.provenance.raw_ref,
            event_ids=[event.event_id],
            entity_ids=[],
            observed_at=event.event_time,
            collected_at=event.ingested_time,
            producer="test",
            producer_version="1",
            reliability="direct",
        )
        for event in events
    ]


def test_timestamp_parser_supports_testbed_formats():
    assert parse_timestamp("09/Sep/2026:15:56:04 +0800").isoformat() == "2026-09-09T07:56:04+00:00"
    assert parse_timestamp("09/Sep/2026 15:56:22").tzinfo is not None
    assert parse_timestamp(1788940564000).tzinfo == timezone.utc


def test_auditd_uses_canonical_process_start_and_best_path():
    payload = "\n".join([
        'type=SYSCALL msg=audit(1788939734.337:180): arch=c000003e syscall=257 success=yes exit=3 pid=2711 ppid=1 uid=0 euid=0 comm="tar" exe="/usr/bin/tar" items=2',
        'type=PATH msg=audit(1788939734.337:180): item=0 name="/tmp" nametype=PARENT',
        'type=PATH msg=audit(1788939734.337:180): item=1 name="/tmp/archive.tar.gz" nametype=CREATE',
        'type=PROCTITLE msg=audit(1788939734.337:180): proctitle=74617200637A66002F746D702F617263686976652E7461722E677A',
    ])
    event = AuditdAdapter().normalize(_raw("auditd", "audit.log", payload, 1788939734.337))[0]
    assert event.action == "file.create"
    assert event.object.ref.display_name == "/tmp/archive.tar.gz"


def test_flow_based_scan_does_not_require_actor_process():
    rows = [
        {"ts": 1788939734 + index, "uid": "scan-%s" % index, "id.orig_h": "10.0.1.50", "id.resp_h": "10.0.2.%s" % index, "id.orig_p": 40000 + index, "id.resp_p": 80, "proto": "tcp"}
        for index in range(1, 5)
    ]
    events = [ZeekAdapter().normalize(_raw("zeek", "zeek.conn", row, row["ts"]))[0] for row in rows]
    detections = FlowNetworkServiceScanningRule(min_targets=4, window_seconds=300).evaluate("run", events, [], _evidence(events))
    assert len(detections) == 1
    assert detections[0].feature_values["scan_type"] == "multi_host"


def test_sensitive_paths_are_policy_globs(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_SENSITIVE_PATHS", "/data/secret/**")
    assert SensitiveFileCollectionRule._matches_sensitive_path("/data/secret/customer_data.txt")
    assert not SensitiveFileCollectionRule._matches_sensitive_path("/data/public/customer_data.txt")


def test_internal_cross_zone_service_destination_is_candidate():
    assert ServiceProcessExternalConnectionRule._is_unexpected_destination("10.0.2.208", "10.0.1.170")
    assert not ServiceProcessExternalConnectionRule._is_unexpected_destination("10.0.2.208", "10.0.2.25")


def test_analysis_upload_pcap_tshark_fallback_produces_zeek_events(tmp_path, monkeypatch):
    monkeypatch.setattr("app.analysis.service.shutil.which", lambda name: "fake-tshark" if name == "tshark" else None)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, "1788939734.1\t10.0.1.50\t10.0.2.10\t40000\t\t80\t\tTCP\t128\n", "")

    monkeypatch.setattr("app.analysis.service.subprocess.run", fake_run)
    client = TestClient(create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False)))
    uploaded = client.post("/api/v1/analysis/upload", files={"file": ("flow.pcap", b"\xd4\xc3\xb2\xa1", "application/octet-stream")})
    task = uploaded.json()["data"]
    started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
    assert started.json()["data"]["result"]["normalized_events"] == 1
    assert started.json()["data"]["result"]["network_events"] == 1


def test_analysis_python_pcap_fallback_produces_network_flow(tmp_path, monkeypatch):
    monkeypatch.setattr("app.analysis.service.shutil.which", lambda _: None)
    pcap = tmp_path / "flow.pcap"
    packet = _ethernet_ipv4_tcp_packet("10.0.1.50", "10.0.2.10", 40000, 80)
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1788939734, 100000, len(packet), len(packet)) + packet)
    service = AnalysisTaskService(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", neo4j_enabled=False), SQLiteRepository(tmp_path / "db.sqlite"), InMemoryGraphProjector())
    rows = list(service._pcap_payloads(pcap))
    assert rows[0]["_dataset"] == "zeek.conn"
    assert rows[0]["id.orig_h"] == "10.0.1.50"
    event = ZeekAdapter().normalize(_raw("zeek", "zeek.conn", rows[0], rows[0]["ts"]))[0]
    assert event.action == "network.flow"


def test_windows_4672_is_privilege_assigned_detection_candidate():
    xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4672</EventID><TimeCreated SystemTime='2026-09-09T08:00:00Z'/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>N7-Office</Computer></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetLogonId'>0x1</Data><Data Name='PrivilegeList'>SeDebugPrivilege</Data></EventData></Event>"
    event = WindowsSecurityAdapter().normalize(_raw("windows_security", "windows.security.xml", xml, "2026-09-09T08:00:00Z"))[0]
    assert event.action == "auth.privilege_assigned"
    detections = PrivilegeEscalationRule().evaluate("run", [event], [], _evidence([event]))
    assert detections[0].rule_id == "det.host.privilege_escalation"


def test_c2_candidate_requires_request_semantics_not_dataset_name():
    event = ApplicationWebAdapter().normalize(_raw("application", "c2.http", {"timestamp": "2026-09-09T08:00:00Z", "src_ip": "10.0.1.50", "dst_ip": "10.0.2.10", "uri": "/index.html", "method": "GET"}, "2026-09-09T08:00:00Z"))[0]
    assert HttpC2CandidateRule().evaluate("run", [event], [], _evidence([event])) == []


def test_analysis_upload_evtx_uses_wevtutil_xml(tmp_path, monkeypatch):
    monkeypatch.setattr("app.analysis.service.shutil.which", lambda name: "wevtutil" if name == "wevtutil" else None)
    xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-09-09T08:00:00Z'/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>N7-Office</Computer></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetLogonId'>0x1</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>10.0.1.170</Data></EventData></Event>"

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, xml, "")

    monkeypatch.setattr("app.analysis.service.subprocess.run", fake_run)
    client = TestClient(create_app(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False)))
    uploaded = client.post("/api/v1/analysis/upload", files={"file": ("n7_security.evtx", b"evtx", "application/octet-stream")})
    task = uploaded.json()["data"]
    started = client.post("/api/v1/analysis/tasks/%s/start" % task["task_id"])
    assert started.json()["data"]["result"]["normalized_events"] == 1


def test_attack_mapping_conservative_for_privileged_logon_and_memory_protect(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False)
    pipeline = build_pipeline(settings, SQLiteRepository(settings.database_path), InMemoryGraphProjector())
    provider = pipeline.detection.mappings.provider
    assert provider.mappings()["det.auth.remote_interactive_logon"] == []
    assert provider.mappings()["det.host.privilege_escalation"] == []


def _ethernet_ipv4_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src = bytes(map(int, src_ip.split(".")))
    dst = bytes(map(int, dst_ip.split(".")))
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 0, 0, 0x5000, 1024, 0, 0)
    total_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 6, 0, src, dst)
    return eth + ip + tcp


def test_archive_zip_slip_is_rejected(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../evil.log", "x")
    service = AnalysisTaskService(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", neo4j_enabled=False), SQLiteRepository(tmp_path / "db.sqlite"), InMemoryGraphProjector())
    try:
        service.create_from_upload("bad.zip", archive.read_bytes())
        raise AssertionError("zip slip archive should be rejected")
    except ValueError as exc:
        assert "unsafe archive member path" in str(exc)


def test_chinese_evidence_note_is_evaluation_only(tmp_path):
    note = tmp_path / "TraceGuard_八节点靶场攻击证据说明.md"
    note.write_text('10.0.1.169 - - [09/Sep/2026:15:56:04 +0800] "GET /admin HTTP/1.1" 404 1', encoding="utf-8")
    service = AnalysisTaskService(Settings(data_dir=tmp_path, database_path=tmp_path / "db.sqlite", raw_archive_dir=tmp_path / "raw", neo4j_enabled=False), SQLiteRepository(tmp_path / "db.sqlite"), InMemoryGraphProjector())
    recognized = service._recognize(note)
    assert recognized.evaluation_only
    assert recognized.source_kind is None
