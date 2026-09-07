from pathlib import Path

from app.normalizers import AuditdAdapter, NormalizerRegistry, SysmonAdapter, WindowsSecurityAdapter, WazuhAdapter, ZeekAdapter
from app.scenarios import load_scenario


SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "powershell_cross_source"


def test_real_format_sysmon_and_zeek_fixtures_normalize():
    raws = load_scenario(SCENARIO)
    registry = NormalizerRegistry([WindowsSecurityAdapter(), SysmonAdapter(), ZeekAdapter()])
    events = [event for raw in raws for event in registry.normalize(raw)]
    assert [event.action for event in events] == ["auth.logon", "process.start", "network.connect", "network.flow"]
    process = events[1]
    assert process.actor.process.attributes["process_guid"].startswith("{")
    assert process.actor.parent_process.display_name.endswith("cmd.exe")
    assert events[2].network.dst.port == 443
    assert events[3].network.zeek_uid == "C8fbO23r5xZ"


def test_auditd_compound_and_wazuh_fixtures_normalize():
    raws = load_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain")
    registry = NormalizerRegistry([WindowsSecurityAdapter(), SysmonAdapter(), ZeekAdapter(), AuditdAdapter(), WazuhAdapter()])
    events = [event for raw in raws for event in registry.normalize(raw)]
    audit_events = [event for event in events if event.source.kind.value == "auditd"]
    assert [event.action for event in audit_events] == ["process.start", "privilege.change", "file.read", "network.connect"]
    assert audit_events[2].extensions["auditd"]["cwd"] == "/root"
    assert audit_events[2].object.ref.display_name == "/etc/shadow"
    assert audit_events[3].extensions["auditd"]["sockaddr"]["addr"] == "203.0.113.77"
    wazuh = next(event for event in events if event.source.kind.value == "wazuh")
    assert wazuh.action == "registry.modify"
    assert wazuh.object.ref.entity_type == "registry"


def test_host_and_network_behavior_fixture_coverage():
    raws = load_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain")
    registry = NormalizerRegistry([WindowsSecurityAdapter(), SysmonAdapter(), ZeekAdapter(), AuditdAdapter(), WazuhAdapter()])
    events = [event for raw in raws for event in registry.normalize(raw)]
    actions = {event.action for event in events}
    assert {"process.start", "process.stop", "file.create", "file.modify", "file.delete", "file.read", "registry.modify", "auth.privilege_assigned", "privilege.change", "memory.remote_thread", "memory.process_access", "memory.process_tamper"}.issubset(actions)
    assert {"network.flow", "dns.query", "http.request", "icmp.message", "network.file_transfer", "network.anomaly", "security.notice"}.issubset(actions)
