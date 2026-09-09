from typing import Any, Dict, List, Optional

from app.contracts import NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import host_ref, ip_ref, process_ref, provenance, user_ref


class SampleAttackDatasetAdapter:
    name = "sample_attack_dataset"
    version = "1.0.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.dataset and raw.source.dataset == "sample_attack_dataset"

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, dict):
            raise AdapterError("sample attack dataset adapter expects JSON records")
        row: Dict[str, Any] = raw.payload
        event_time = parse_timestamp(row.get("timestamp") or row.get("ts") or raw.event_time_raw or raw.observed_time.isoformat())
        host = host_ref(row.get("host") or raw.source.host_hint, raw.source.sensor_id)
        user = user_ref(row.get("user"), host.entity_id)
        process_name = row.get("process") or row.get("image")
        command_line = row.get("command_line") or row.get("cmdline")
        process = process_ref(host.entity_id, row.get("process_guid"), row.get("pid"), process_name, event_time.isoformat())
        network = self._network_context(host.entity_id, row)
        action = str(row.get("action") or row.get("event_type") or "dataset.event")
        object_ref = None
        object_type = "other"
        if network:
            object_ref = self._destination_ref(row)
            object_type = "network"
        elif process:
            object_ref = process
            object_type = "process"
        event_id = stable_id("evt", raw.source.kind.value, raw.source.dataset, raw.source_record_id or raw.raw_id)
        return [UnifiedSecurityEvent(
            event_id=event_id,
            event_time=event_time,
            observed_time=raw.observed_time,
            ingested_time=raw.ingested_time,
            time=TimeContext(original=raw.event_time_raw or row.get("ts"), uncertainty_ms=10, quality="estimated"),
            source=raw.source,
            host=host,
            actor=ActorContext(user=user, process=process),
            object=ObjectContext(type=object_type, ref=object_ref),
            network=network,
            action=action,
            event_type=str(row.get("event_type") or action),
            outcome=str(row.get("outcome") or "unknown"),
            severity=str(row.get("severity") or "informational"),
            message=command_line or row.get("message") or action,
            tags=["dataset", "sample", "replay"],
            extensions={"sample_attack_dataset": {
                "source_ip": row.get("source_ip") or row.get("src_ip"),
                "destination_ip": row.get("destination_ip") or row.get("dst_ip"),
                "user": row.get("user"),
                "process": process_name,
                "command_line": command_line,
                "protocol": row.get("protocol") or row.get("network_protocol"),
            }},
            provenance=provenance(raw, self.name, self.version),
        )]

    def _network_context(self, host_id: str, row: Dict[str, Any]) -> Optional[NetworkContext]:
        src_ip = row.get("source_ip") or row.get("src_ip")
        dst_ip = row.get("destination_ip") or row.get("dst_ip")
        if not (src_ip or dst_ip):
            return None
        protocol = str(row.get("protocol") or row.get("network_protocol") or "tcp").lower()
        if protocol not in {"tcp", "udp", "icmp"}:
            protocol = "other"
        dst_port = self._port(row.get("destination_port") or row.get("dst_port"))
        src_port = self._port(row.get("source_port") or row.get("src_port"))
        session_id = stable_id("session", self.name, src_ip, src_port, dst_ip, dst_port, protocol)
        return NetworkContext(
            session_id=session_id,
            direction="outbound",
            transport=protocol,
            application=self._application(dst_port),
            src=NetworkEndpoint(ip=src_ip, port=src_port, host_id=host_id),
            dst=NetworkEndpoint(ip=dst_ip, port=dst_port),
        )

    @staticmethod
    def _port(value: Any) -> Optional[int]:
        if value is None:
            return None
        return int(value)

    @staticmethod
    def _application(port: Optional[int]) -> str:
        if port == 53:
            return "dns"
        if port in {80, 8080}:
            return "http"
        if port == 443:
            return "https"
        if port == 22:
            return "ssh"
        if port == 445:
            return "smb"
        if port == 3389:
            return "rdp"
        if port == 25:
            return "smtp"
        return "other"

    @staticmethod
    def _destination_ref(row: Dict[str, Any]):
        dst_ip = row.get("destination_ip") or row.get("dst_ip")
        if not dst_ip:
            return None
        try:
            return ip_ref(dst_ip)
        except ValueError:
            return None
