from typing import Any, Dict, List, Optional, Tuple

from app.contracts import EntityRef, NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import file_ref, ip_ref, provenance, user_ref


ACTION_MAP = {
    "aue_accept": "network.accept",
    "aue_chdir": "process.activity",
    "aue_chmod": "file.modify",
    "aue_close": "file.close",
    "aue_connect": "network.connect",
    "aue_execve": "process.start",
    "aue_exit": "process.stop",
    "aue_fcntl": "process.activity",
    "aue_fork": "process.start",
    "aue_lseek": "file.seek",
    "aue_mmap": "memory.map",
    "aue_mprotect": "memory.protect",
    "aue_open_rwtc": "file.open",
    "aue_openat_rwtc": "file.open",
    "aue_pipe": "process.ipc",
    "aue_pread": "file.read",
    "aue_read": "file.read",
    "aue_recvfrom": "network.receive",
    "aue_sendto": "network.send",
    "aue_setegid": "privilege.change",
    "aue_seteuid": "privilege.change",
    "aue_setgid": "privilege.change",
    "aue_setlogin": "privilege.change",
    "aue_setuid": "privilege.change",
    "aue_socketpair": "process.ipc",
    "aue_umask": "process.activity",
    "aue_unlink": "file.delete",
    "aue_vfork": "process.start",
    "aue_write": "file.write",
    "aue_writev": "network.send",
}

NETWORK_ACTIONS = {"network.accept", "network.connect", "network.receive", "network.send"}
FILE_ACTIONS = {"file.close", "file.delete", "file.modify", "file.open", "file.read", "file.seek", "file.write", "memory.map", "process.start"}


class DarpaTcE3CadetsAdapter:
    name = "darpa_tc_e3_cadets"
    version = "1.0.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.dataset and raw.source.dataset == "darpa_tc_e3_cadets"

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, dict):
            raise AdapterError("DARPA TC E3 CADets adapter expects JSON records")
        row: Dict[str, Any] = raw.payload
        event_time = parse_timestamp(row.get("timestamp") or raw.event_time_raw or raw.observed_time.isoformat())
        raw_action = str(row.get("action") or row.get("event_type") or "").lower()
        warnings: List[str] = []
        action = ACTION_MAP.get(raw_action)
        if not action:
            action = "dataset.unknown"
            warnings.append("unknown darpa action: %s" % raw_action)

        host = self._host_ref(row, raw)
        user = user_ref(row.get("user"), host.entity_id)
        subject_process = self._process_ref(host.entity_id, row.get("subject_id"), row.get("process"), row)
        parent_process = self._process_ref(host.entity_id, row.get("parent_subject_id"), row.get("parent_process"), row)
        object_ref, object_type = self._object_ref(host.entity_id, row, action, subject_process)
        actor_process = subject_process
        if action == "process.start" and row.get("object_id"):
            parent_process = subject_process
            actor_process = self._process_ref(host.entity_id, row.get("object_id"), row.get("process"), row)
            object_ref, object_type = actor_process, "process"
        network = self._network_context(host.entity_id, row, action)
        if network:
            object_ref = self._destination_ref(row) or object_ref
            object_type = "network"

        return [UnifiedSecurityEvent(
            event_id=stable_id("evt", raw.raw_id),
            event_time=event_time,
            observed_time=raw.observed_time,
            ingested_time=raw.ingested_time,
            time=TimeContext(original=row.get("timestamp"), uncertainty_ms=0, quality="synced"),
            source=raw.source,
            host=host,
            actor=ActorContext(user=user, process=actor_process, parent_process=parent_process),
            object=ObjectContext(type=object_type, ref=object_ref),
            network=network,
            action=action,
            event_type="darpa_tc_e3.%s" % str(row.get("event_type") or "event"),
            outcome=self._outcome(row),
            severity="informational",
            message=self._message(row, action),
            tags=["dataset", "darpa", "tc-e3", "cadets"],
            extensions={"dataset": self._extensions(row, raw_action, action)},
            provenance=provenance(raw, self.name, self.version, warnings),
        )]

    @staticmethod
    def _host_ref(row: Dict[str, Any], raw: RawEventEnvelope) -> EntityRef:
        host = str(row.get("host") or raw.source.host_hint or raw.source.sensor_id).lower()
        return EntityRef(
            entity_type="host",
            entity_id=stable_id("host", "darpa_tc_e3_cadets", host),
            source_ids=[host, raw.source.sensor_id],
            display_name=host,
            attributes={"host_uuid": host, "dataset": "darpa_tc_e3_cadets"},
            identity_quality="exact",
        )

    @staticmethod
    def _process_ref(host_id: str, subject_id: Optional[str], name: Optional[str], row: Dict[str, Any]) -> Optional[EntityRef]:
        if not subject_id and not name:
            return None
        properties = row.get("evidence", {}).get("properties", {}) if isinstance(row.get("evidence"), dict) else {}
        display = name or properties.get("exec") or subject_id
        identity = subject_id or "%s|%s|%s" % (host_id, display, row.get("timestamp_ns"))
        return EntityRef(
            entity_type="process",
            entity_id=stable_id("proc", host_id, identity),
            source_ids=[subject_id] if subject_id else [],
            display_name=display,
            attributes={
                "subject_id": subject_id,
                "image": display,
                "process": display,
                "ppid": properties.get("ppid"),
                "cmdline": properties.get("cmdLine"),
            },
            identity_quality="exact" if subject_id else "provisional",
        )

    def _object_ref(self, host_id: str, row: Dict[str, Any], action: str, subject_process: Optional[EntityRef]) -> Tuple[Optional[EntityRef], Optional[str]]:
        if action in FILE_ACTIONS:
            if action == "process.start" and row.get("object_path"):
                return file_ref(host_id, row.get("object_path")), "file"
            if action.startswith("file.") or action == "memory.map":
                return file_ref(host_id, row.get("object_path")), "file"
        if action == "memory.protect":
            return subject_process, "memory"
        if action.startswith("privilege."):
            return subject_process, "process"
        if action.startswith("process."):
            return subject_process, "process"
        return None, "other"

    @staticmethod
    def _endpoint(value: Optional[Dict[str, Any]], host_id: Optional[str] = None) -> NetworkEndpoint:
        if not isinstance(value, dict):
            return NetworkEndpoint(host_id=host_id)
        port = value.get("port")
        return NetworkEndpoint(ip=value.get("ip"), port=int(port) if port is not None else None, host_id=host_id)

    def _network_context(self, host_id: str, row: Dict[str, Any], action: str) -> Optional[NetworkContext]:
        if action not in NETWORK_ACTIONS:
            return None
        src = self._endpoint(row.get("source"), host_id if action in {"network.connect", "network.send"} else None)
        dst = self._endpoint(row.get("destination"), host_id if action in {"network.accept", "network.receive"} else None)
        if not (src.ip or dst.ip):
            return None
        size = row.get("evidence", {}).get("size") if isinstance(row.get("evidence"), dict) else None
        session_id = stable_id(
            "session", "darpa_tc_e3_cadets", row.get("host"), row.get("subject_id"),
            row.get("object_id") or row.get("object2_id"), src.ip, src.port, dst.ip, dst.port,
        )
        return NetworkContext(
            session_id=session_id,
            direction="inbound" if action in {"network.accept", "network.receive"} else "outbound",
            transport="tcp",
            application=self._application(dst.port),
            src=src,
            dst=dst,
            bytes_sent=int(size) if action in {"network.send"} and size is not None and int(size) >= 0 else None,
            bytes_received=int(size) if action in {"network.receive"} and size is not None and int(size) >= 0 else None,
        )

    @staticmethod
    def _application(port: Optional[int]) -> Optional[str]:
        if port in {80, 8080}:
            return "http"
        if port == 443:
            return "https"
        if port == 22:
            return "ssh"
        if port == 53:
            return "dns"
        return "other"

    @staticmethod
    def _destination_ref(row: Dict[str, Any]) -> Optional[EntityRef]:
        endpoint = row.get("destination") if isinstance(row.get("destination"), dict) else None
        if not endpoint or not endpoint.get("ip"):
            return None
        try:
            return ip_ref(endpoint["ip"])
        except ValueError:
            return None

    @staticmethod
    def _outcome(row: Dict[str, Any]) -> str:
        properties = row.get("evidence", {}).get("properties", {}) if isinstance(row.get("evidence"), dict) else {}
        value = properties.get("return_value")
        if value is None:
            return "unknown"
        try:
            return "success" if int(value) >= 0 else "failure"
        except (TypeError, ValueError):
            return "unknown"

    @staticmethod
    def _message(row: Dict[str, Any], action: str) -> str:
        properties = row.get("evidence", {}).get("properties", {}) if isinstance(row.get("evidence"), dict) else {}
        command = properties.get("cmdLine")
        if command:
            return command
        if row.get("object_path"):
            return "%s %s by %s" % (action, row.get("object_path"), row.get("process") or "unknown")
        if row.get("source") or row.get("destination"):
            return "%s %s -> %s by %s" % (action, row.get("source"), row.get("destination"), row.get("process") or "unknown")
        return "%s by %s" % (action, row.get("process") or "unknown")

    @staticmethod
    def _extensions(row: Dict[str, Any], raw_action: str, mapped_action: str) -> Dict[str, Any]:
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        return {
            "dataset_id": "darpa_tc_e3_cadets",
            "dataset_file": row.get("dataset_file"),
            "dataset_index": row.get("dataset_index"),
            "original_event_id": row.get("event_id"),
            "original_event_type": row.get("original_event_type"),
            "normalized_event_type": row.get("event_type"),
            "original_action": raw_action,
            "mapped_action": mapped_action,
            "subject_id": row.get("subject_id"),
            "parent_subject_id": row.get("parent_subject_id"),
            "object_id": row.get("object_id"),
            "object2_id": row.get("object2_id"),
            "object_path": row.get("object_path"),
            "object2_path": row.get("object2_path"),
            "provider": row.get("provider"),
            "quality_flags": row.get("quality_flags") or [],
            "timestamp_ns": row.get("timestamp_ns"),
            "raw_location": row.get("raw_location"),
            "cdm": {
                "type": evidence.get("type"),
                "name": evidence.get("name"),
                "properties": evidence.get("properties") or {},
                "size": evidence.get("size"),
            },
        }
