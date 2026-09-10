from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.contracts import Evidence, SourceDescriptor, TimeContext, UnifiedSecurityEvent
from app.contracts.common import EntityRef, NetworkContext, NetworkEndpoint, SourceKind
from app.contracts.events import ActorContext, EventProvenance, ObjectContext
from app.detection.rules import (
    AnchoredPeerTrafficRule,
    ArchiveTransferCorrelationRule,
    BeaconingSessionRule,
    CollectionArchiveCorrelationRule,
    ExecutionCleanupRule,
    ForkExecTempRule,
    IngressToolTransferRule,
    PermissionThenExecutionRule,
    SensitiveReadBurstRule,
    ServiceSpawnShellRule,
    SuspiciousFileStagingRule,
    SuspiciousServiceSessionRule,
    TempExecNetworkRule,
    TempFileLifecycleRule,
)


BASE = datetime(2026, 9, 11, 1, 0, tzinfo=timezone.utc)
SOURCE = SourceDescriptor(kind=SourceKind.dataset, product="test", dataset="synthetic", sensor_id="sensor")


def _ref(entity_type, entity_id, display=None, **attrs):
    return EntityRef(entity_type=entity_type, entity_id=entity_id, display_name=display or entity_id, attributes=attrs, identity_quality="exact")


def _event(index, action, path=None, proc="proc", parent=None, host="host", network=None, original_action=None, command=None):
    now = BASE + timedelta(seconds=index)
    process = _ref("process", f"proc_{proc}", proc, image=proc)
    parent_ref = _ref("process", f"proc_{parent}", parent, image=parent) if parent else None
    obj = _ref("file", f"file_{host}_{path}", path, normalized_path=path) if path else None
    dataset = {"original_action": original_action, "object_path": path}
    cdm = {"properties": {"cmdLine": command}} if command else {"properties": {}}
    dataset["cdm"] = cdm
    return UnifiedSecurityEvent(
        event_id=f"evt_{index}_{action.replace('.', '_')}",
        event_time=now,
        observed_time=now,
        ingested_time=now,
        time=TimeContext(original=now.isoformat(), quality="synced"),
        source=SOURCE,
        host=_ref("host", host, host),
        actor=ActorContext(process=process, parent_process=parent_ref),
        object=ObjectContext(type="file" if obj else "other", ref=obj),
        network=network,
        action=action,
        event_type="synthetic",
        outcome="success",
        severity="informational",
        message=command or action,
        extensions={"dataset": dataset},
        provenance=EventProvenance(raw_id=f"raw_{index}", raw_ref=f"raw://{index}", raw_sha256=f"sha_{index}", parser_name="test", parser_version="1"),
    )


def _net(index, action, proc="proc", parent=None, host="host", src="10.0.1.10", dst="10.0.2.20", direction="outbound", size=128, port=443):
    network = NetworkContext(
        session_id=f"sess_{proc}_{src}_{dst}_{port}",
        direction=direction,
        transport="tcp",
        application="https",
        src=NetworkEndpoint(ip=src, port=50000, host_id=host if direction == "outbound" else None),
        dst=NetworkEndpoint(ip=dst, port=port, host_id=host if direction == "inbound" else None),
        bytes_sent=size if action == "network.send" else None,
        bytes_received=size if action == "network.receive" else None,
    )
    return _event(index, action, proc=proc, parent=parent, host=host, network=network)


def _evidence(events):
    return [
        Evidence(evidence_id=f"evd_{event.event_id}", kind="normalized_event", source_ref=event.provenance.raw_ref, event_ids=[event.event_id], observed_at=event.event_time, collected_at=event.ingested_time, producer="test", producer_version="1", reliability="direct")
        for event in events
    ]


def _run(rule, events):
    return rule.evaluate("run", events, [], _evidence(events))


def test_temp_file_lifecycle_requires_correlated_temp_activity():
    events = [_event(1, "file.open", "/tmp/tool"), _event(2, "file.modify", "/tmp/tool"), _event(3, "process.start", "/tmp/tool")]
    detections = _run(TempFileLifecycleRule(), events)
    assert len(detections) == 1
    assert set(detections[0].event_ids) == {event.event_id for event in events}
    assert _run(TempFileLifecycleRule(), [_event(1, "file.open", "/tmp/readme")]) == []


def test_permission_then_execution_requires_same_path():
    assert _run(PermissionThenExecutionRule(), [_event(1, "file.modify", "/tmp/tool"), _event(30, "process.start", "/tmp/tool")])
    assert _run(PermissionThenExecutionRule(), [_event(1, "file.modify", "/tmp/tool"), _event(30, "process.start", "/tmp/other")]) == []


def test_execution_cleanup_requires_prior_temp_execution():
    assert _run(ExecutionCleanupRule(), [_event(1, "process.start", "/tmp/tool"), _event(40, "file.delete", "/tmp/tool")])
    assert _run(ExecutionCleanupRule(), [_event(1, "file.delete", "/tmp/tool")]) == []


def test_service_spawn_shell_requires_service_parent_lineage():
    assert _run(ServiceSpawnShellRule(), [_event(1, "process.start", proc="/bin/sh", parent="nginx")])
    assert _run(ServiceSpawnShellRule(), [_event(1, "process.start", proc="/bin/sh", parent="sshd")]) == []


def test_temp_exec_network_requires_temp_execution_and_peer():
    events = [_event(1, "process.start", "/tmp/tool", proc="tool"), _net(30, "network.connect", proc="tool")]
    assert _run(TempExecNetworkRule(), events)
    assert _run(TempExecNetworkRule(), [_net(30, "network.connect", proc="tool")]) == []


def test_suspicious_service_session_requires_outbound_anchor_and_bidirectional_peer():
    events = [_net(1, "network.connect", proc="nginx"), _net(5, "network.send", proc="nginx"), _net(8, "network.receive", proc="nginx")]
    detection = _run(SuspiciousServiceSessionRule(), events)[0]
    assert set(detection.event_ids) == {event.event_id for event in events}
    inbound = [_net(1, "network.receive", proc="nginx", direction="inbound", src="10.0.2.20", dst="10.0.1.10")]
    assert _run(SuspiciousServiceSessionRule(), inbound) == []


def test_anchored_peer_traffic_requires_high_risk_anchor():
    events = [_event(1, "process.start", "/tmp/tool", proc="tool"), _net(2, "network.send", proc="tool"), _net(3, "network.receive", proc="tool")]
    assert _run(AnchoredPeerTrafficRule(), events)
    assert _run(AnchoredPeerTrafficRule(), [_net(2, "network.send", proc="tool"), _net(3, "network.receive", proc="tool")]) == []


def test_beaconing_session_requires_periodic_outbound_anchor():
    events = [_net(index * 10, "network.connect", proc="agent") for index in range(1, 7)]
    detection = _run(BeaconingSessionRule(), events)[0]
    assert detection.feature_values["request_count"] == 6
    jitter = [_net(index, "network.connect", proc="agent") for index in (1, 2, 50, 55, 140)]
    assert _run(BeaconingSessionRule(), jitter) == []


def test_sensitive_read_burst_requires_three_distinct_sensitive_paths(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_SENSITIVE_PATHS", "/etc/**;/home/*/.ssh/**")
    events = [_event(1, "file.read", "/etc/passwd"), _event(2, "file.read", "/etc/shadow"), _event(3, "file.read", "/home/alice/.ssh/id_rsa")]
    assert _run(SensitiveReadBurstRule(), events)
    assert _run(SensitiveReadBurstRule(), events[:2]) == []


def test_collection_archive_correlation_requires_prior_sensitive_read(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_SENSITIVE_PATHS", "/etc/**")
    events = [_event(1, "file.read", "/etc/passwd", proc="tar"), _event(20, "process.start", proc="tar", command="tar czf /tmp/a.tgz /etc")]
    assert _run(CollectionArchiveCorrelationRule(), events)
    assert _run(CollectionArchiveCorrelationRule(), [_event(20, "process.start", proc="tar", command="tar czf /tmp/a.tgz /var/log")]) == []


def test_archive_transfer_correlation_requires_archive_and_network(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_SENSITIVE_PATHS", "/etc/**")
    events = [_event(1, "file.read", "/etc/passwd", proc="tar"), _event(20, "process.start", proc="tar", command="tar czf /tmp/a.tgz /etc"), _net(50, "network.send", proc="tar", size=80000)]
    assert _run(ArchiveTransferCorrelationRule(), events)
    assert _run(ArchiveTransferCorrelationRule(), [_event(20, "process.start", proc="tar", command="tar czf /tmp/a.tgz /etc")]) == []


def test_ingress_tool_transfer_requires_receive_write_execute_chain():
    events = [_net(1, "network.receive", proc="nginx", direction="inbound", src="10.0.2.20", dst="10.0.1.10"), _event(20, "file.write", "/tmp/tool", proc="nginx"), _event(50, "process.start", "/tmp/tool", proc="tool", parent="nginx")]
    assert _run(IngressToolTransferRule(), events)
    assert _run(IngressToolTransferRule(), [_net(1, "network.receive", proc="nginx"), _event(20, "file.write", "/tmp/tool", proc="nginx")]) == []


def test_suspicious_file_staging_requires_sequence_not_single_write():
    events = [_event(1, "file.open", "/tmp/tool"), _event(2, "file.write", "/tmp/tool"), _event(3, "file.modify", "/tmp/tool"), _event(20, "process.start", "/tmp/tool")]
    assert _run(SuspiciousFileStagingRule(), events)
    assert _run(SuspiciousFileStagingRule(), [_event(2, "file.write", "/tmp/tool")]) == []


def test_fork_exec_temp_requires_risky_exec_after_fork():
    events = [_event(1, "process.start", proc="parent", original_action="aue_vfork"), _event(2, "process.start", "/tmp/tool", proc="tool", parent="parent", original_action="aue_execve")]
    assert _run(ForkExecTempRule(), events)
    benign = [_event(1, "process.start", proc="parent", original_action="aue_vfork"), _event(2, "process.start", "/usr/bin/true", proc="true", parent="parent", original_action="aue_execve")]
    assert _run(ForkExecTempRule(), benign) == []


def test_detection_chain_agent_logic_do_not_read_evaluation_labels():
    root = Path(__file__).parents[1] / "app"
    banned = ("attack_label", "selection_reason", "ground_truth", "ioc_match")
    checked = []
    for folder in ("detection", "attack", "agents"):
        for path in (root / folder).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            checked.append(path)
            for token in banned:
                assert token not in text, f"{path} must not read evaluation-only field {token}"
    assert checked
