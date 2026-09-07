from typing import Any, Dict, List

from app.contracts import RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .auditd import AuditdAdapter
from .base import AdapterError
from .helpers import file_ref, host_ref, process_ref, provenance, registry_ref, user_ref


class WazuhAdapter:
    name = "wazuh"
    version = "1.1.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.wazuh

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, dict):
            raise AdapterError("Wazuh adapter expects alert JSON")
        payload: Dict[str, Any] = raw.payload
        data = payload.get("data") or {}
        if isinstance(data, dict) and (data.get("audit") or data.get("full_log") or payload.get("full_log")):
            text = data.get("full_log") or payload.get("full_log")
            if isinstance(text, str) and "msg=audit(" in text:
                audit_raw = raw.model_copy(update={"source": raw.source.model_copy(update={"kind": SourceKind.auditd}), "payload": text, "payload_format": "text"})
                return [event.model_copy(update={"source": raw.source, "provenance": provenance(raw, self.name, self.version), "tags": sorted(set(event.tags + ["wazuh"]))}) for event in AuditdAdapter().normalize(audit_raw)]
        win = data.get("win") or {}
        system = win.get("system") or {}
        eventdata = win.get("eventdata") or {}
        try:
            event_number = int(system.get("eventID") or system.get("eventId") or data.get("event_id") or 0)
        except (TypeError, ValueError):
            event_number = 0
        mapping = {
            1: ("process.start", "process"), 5: ("process.stop", "process"), 8: ("memory.remote_thread", "memory"),
            10: ("memory.process_access", "memory"), 11: ("file.create", "file"), 12: ("registry.create", "registry"),
            13: ("registry.modify", "registry"), 14: ("registry.rename", "registry"), 23: ("file.delete", "file"),
            25: ("memory.process_tamper", "memory"), 4624: ("auth.logon", "user"), 4625: ("auth.logon", "user"),
            4672: ("auth.privilege_assigned", "user"),
        }
        action, object_type = mapping.get(event_number, ("security.alert", "other"))
        timestamp = payload.get("timestamp") or system.get("systemTime") or raw.event_time_raw or raw.observed_time.isoformat()
        event_time = parse_timestamp(timestamp)
        hostname = ((payload.get("agent") or {}).get("name") or system.get("computer") or raw.source.host_hint)
        host = host_ref(hostname, raw.source.sensor_id)
        process = process_ref(host.entity_id, eventdata.get("processGuid") or eventdata.get("sourceProcessGuid"), eventdata.get("processId") or eventdata.get("sourceProcessId"), eventdata.get("image") or eventdata.get("sourceImage"), event_time.isoformat())
        user = user_ref(eventdata.get("user") or eventdata.get("targetUserName"), host.entity_id, eventdata.get("targetUserSid"))
        object_ref = process
        if object_type == "file": object_ref = file_ref(host.entity_id, eventdata.get("targetFilename"))
        if object_type == "registry": object_ref = registry_ref(host.entity_id, eventdata.get("targetObject"))
        if object_type == "user": object_ref = user
        level = int((payload.get("rule") or {}).get("level") or 0)
        return [UnifiedSecurityEvent(
            event_id=stable_id("evt", "wazuh", raw.source.sensor_id, raw.source_record_id, raw.raw_id), event_time=event_time,
            observed_time=raw.observed_time, ingested_time=raw.ingested_time, time=TimeContext(original=timestamp, uncertainty_ms=25, quality="synced"),
            source=raw.source, host=host, actor=ActorContext(user=user, process=process), object=ObjectContext(type=object_type, ref=object_ref),
            action=action, event_type="wazuh.alert.%s" % event_number, outcome="failure" if event_number == 4625 else "success",
            severity="critical" if level >= 13 else "high" if level >= 10 else "medium" if level >= 7 else "low",
            message=(payload.get("rule") or {}).get("description") or eventdata.get("commandLine") or action,
            tags=["wazuh", "windows" if win else "linux"], extensions={"wazuh": payload, "event_id": event_number, "eventdata": eventdata}, provenance=provenance(raw, self.name, self.version),
        )]
