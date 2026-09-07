from typing import List

from app.contracts import EntityRef, NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import domain_ref, file_ref, host_ref, ip_ref, process_ref, provenance, registry_ref, user_ref
from .windows_xml import parse_windows_event


class SysmonAdapter:
    name = "sysmon"
    version = "1.2.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.sysmon

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, str):
            raise AdapterError("Sysmon adapter expects exported Windows Event XML")
        parsed = parse_windows_event(raw.payload)
        data = parsed["data"]
        event_number = parsed["event_id"]
        event_time = parse_timestamp(data.get("UtcTime") or parsed["time_created"] or raw.observed_time.isoformat())
        host = host_ref(parsed["computer"] or raw.source.host_hint, raw.source.sensor_id)
        process = process_ref(host.entity_id, data.get("ProcessGuid") or data.get("SourceProcessGuid"), data.get("ProcessId") or data.get("SourceProcessId"), data.get("Image") or data.get("SourceImage"), event_time.isoformat())
        user = user_ref(data.get("User"), host.entity_id)
        parent = process_ref(host.entity_id, data.get("ParentProcessGuid"), data.get("ParentProcessId"), data.get("ParentImage"), event_time.isoformat())
        action_by_id = {
            1: ("process.start", "process"), 3: ("network.connect", "network"), 5: ("process.stop", "process"),
            8: ("memory.remote_thread", "memory"), 10: ("memory.process_access", "memory"),
            11: ("file.create", "file"), 15: ("file.modify", "file"),
            12: ("registry.create_delete", "registry"), 13: ("registry.modify", "registry"), 14: ("registry.rename", "registry"),
            22: ("dns.query", "network"), 23: ("file.delete", "file"), 25: ("memory.process_tamper", "memory"), 26: ("file.delete", "file"),
        }
        if event_number not in action_by_id:
            return []
        action, object_type = action_by_id[event_number]
        network = None
        object_ref = process if object_type == "process" else None
        if event_number == 3:
            src_ip, dst_ip = data.get("SourceIp"), data.get("DestinationIp")
            network = NetworkContext(
                direction="outbound" if data.get("Initiated", "true").lower() == "true" else "inbound",
                transport=(data.get("Protocol") or "other").lower(),
                application="https" if str(data.get("DestinationPort")) == "443" else "other",
                src=NetworkEndpoint(ip=src_ip, port=int(data["SourcePort"]) if data.get("SourcePort") else None, host_id=host.entity_id),
                dst=NetworkEndpoint(ip=dst_ip, port=int(data["DestinationPort"]) if data.get("DestinationPort") else None),
            )
            object_ref = ip_ref(dst_ip) if dst_ip else None
        elif event_number == 22:
            object_ref = domain_ref(data.get("QueryName"))
            network = NetworkContext(
                direction="outbound", transport="udp", application="dns",
                src=NetworkEndpoint(host_id=host.entity_id), dst=NetworkEndpoint(),
                dns={"query": data.get("QueryName"), "query_status": data.get("QueryStatus"), "query_results": data.get("QueryResults")},
            )
        elif object_type == "file":
            object_ref = file_ref(host.entity_id, data.get("TargetFilename"))
        elif object_type == "registry":
            object_ref = registry_ref(host.entity_id, data.get("TargetObject") or data.get("NewName"))
            if event_number == 12:
                event_kind = str(data.get("EventType") or "").lower()
                action = "registry.delete" if "delete" in event_kind else "registry.create"
        elif object_type == "memory":
            object_ref = process_ref(host.entity_id, data.get("TargetProcessGuid"), data.get("TargetProcessId"), data.get("TargetImage"), event_time.isoformat())
        event_id = stable_id("evt", raw.source.kind.value, raw.source.sensor_id, raw.source_record_id, raw.raw_id, 0)
        return [UnifiedSecurityEvent(
            event_id=event_id, event_time=event_time, observed_time=raw.observed_time, ingested_time=raw.ingested_time,
            time=TimeContext(original=raw.event_time_raw, uncertainty_ms=1, quality="synced"), source=raw.source, host=host,
            actor=ActorContext(user=user, process=process, parent_process=parent), object=ObjectContext(type=object_type, ref=object_ref),
            network=network, action=action, event_type="sysmon.event.%d" % event_number, outcome="success", severity="informational",
            message=data.get("CommandLine") or data.get("TargetFilename") or data.get("TargetObject") or data.get("TargetImage") or data.get("Image"), tags=["windows", "sysmon", object_type], extensions={"sysmon": data, "event_id": event_number},
            provenance=provenance(raw, self.name, self.version),
        )]
