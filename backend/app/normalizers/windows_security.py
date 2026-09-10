from typing import List

from app.contracts import EntityRef, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import asset_aliases, file_ref, host_ref, process_ref, provenance, user_ref
from .windows_xml import parse_windows_event


class WindowsSecurityAdapter:
    name = "windows-security"
    version = "1.1.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.windows_security

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, str):
            raise AdapterError("Windows Security adapter expects exported Event XML")
        parsed = parse_windows_event(raw.payload)
        event_number, data = parsed["event_id"], parsed["data"]
        mapping = {4624: ("auth.logon", "success"), 4625: ("auth.logon", "failure"), 4634: ("auth.logoff", "success"), 4647: ("auth.logoff", "success"), 4672: ("auth.privilege_assigned", "success"), 4663: ("file.access", "success")}
        if event_number not in mapping:
            return []
        action, outcome = mapping[event_number]
        event_time = parse_timestamp(parsed["time_created"] or raw.observed_time.isoformat())
        computer = parsed["computer"]
        if isinstance(computer, str) and computer.lower() in {"localhost", "."}:
            computer = raw.source.host_hint or computer
        host = host_ref(computer or raw.source.host_hint, raw.source.sensor_id, asset_aliases(raw))
        user = user_ref(data.get("TargetUserName"), host.entity_id, data.get("TargetUserSid"))
        session_id = stable_id("session", host.entity_id, data.get("TargetLogonId", "unknown"))
        session_ref = EntityRef(entity_type="session", entity_id=session_id, source_ids=[data.get("TargetLogonId", "")], display_name=data.get("TargetLogonId"), attributes={"logon_type": data.get("LogonType"), "ip_address": data.get("IpAddress")}, identity_quality="exact")
        object_type, object_ref = "user", session_ref
        process = None
        if event_number == 4663:
            object_type, object_ref = "file", file_ref(host.entity_id, data.get("ObjectName"))
            process = process_ref(host.entity_id, None, data.get("ProcessId"), data.get("ProcessName"), event_time.isoformat())
            access = str(data.get("AccessList") or data.get("AccessMask") or "").lower()
            action = "file.delete" if "delete" in access else "file.modify" if any(token in access for token in ("write", "append", "0x2", "0x4")) else "file.read"
        return [UnifiedSecurityEvent(
            event_id=stable_id("evt", raw.source.kind.value, raw.source.sensor_id, raw.source_record_id, raw.raw_id, 0),
            event_time=event_time, observed_time=raw.observed_time, ingested_time=raw.ingested_time,
            time=TimeContext(original=raw.event_time_raw, uncertainty_ms=10, quality="synced"), source=raw.source, host=host,
            actor=ActorContext(user=user, process=process), object=ObjectContext(type=object_type, ref=object_ref), action=action,
            event_type="windows.security.%d" % event_number, outcome=outcome, severity="informational" if outcome == "success" else "low",
            message="Windows logon event %d" % event_number, tags=["windows", "authentication"], extensions={"windows_security": data, "event_id": event_number},
            provenance=provenance(raw, self.name, self.version),
        )]
