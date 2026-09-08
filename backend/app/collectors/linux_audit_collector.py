from pathlib import Path
from typing import List

from app.collectors.base import BaseCollector, non_empty_lines
from app.collectors.envelope import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.time import parse_timestamp
from app.normalizers.auditd import AUDIT_RE


class LinuxAuditCollector(BaseCollector):
    name = "linux_audit"

    def __init__(self, path: Path, sensor_id: str = "linux-audit-01", host_hint: str = "linux-host-01") -> None:
        self.path = Path(path)
        self.sensor_id = sensor_id
        self.host_hint = host_hint

    def collect(self) -> List[RawEventEnvelope]:
        lines = non_empty_lines(self.path.read_text(encoding="utf-8").splitlines())
        groups: dict[str, list[str]] = {}
        order: list[str] = []
        for line in lines:
            match = AUDIT_RE.search(line)
            if not match:
                continue
            key = "%s:%s" % (match.group("timestamp"), match.group("serial"))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(line)
        return [self.parse("\n".join(groups[key])) for key in order]

    def parse(self, record: str) -> RawEventEnvelope:
        match = AUDIT_RE.search(record)
        timestamp = match.group("timestamp") if match else None
        serial = match.group("serial") if match else "unknown"
        source = SourceDescriptor(
            kind="auditd",
            product="Linux Auditd",
            dataset="audit.log",
            sensor_id=self.sensor_id,
            host_hint=self.host_hint,
            source_record_id="audit-%s" % serial,
        )
        return envelope_from_payload(
            source=source,
            payload=record,
            payload_format="text",
            event_time_raw=float(timestamp) if timestamp else None,
            raw_ref="file://%s#audit-%s" % (self.path.as_posix(), serial),
            observed_time=parse_timestamp(float(timestamp)) if timestamp else None,
            labels={"collector": self.name, "supported_events": ["execve", "file_open", "network_connect"]},
        )
