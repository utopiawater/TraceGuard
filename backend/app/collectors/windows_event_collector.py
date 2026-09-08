import html
import json
from pathlib import Path
from typing import Any, Dict, List

from app.collectors.base import BaseCollector
from app.collectors.envelope import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.time import parse_timestamp


class WindowsEventCollector(BaseCollector):
    name = "windows_event"

    def __init__(self, path: Path, sensor_id: str = "windows-endpoint", host_hint: str = "win-client-01.corp.lab") -> None:
        self.path = Path(path)
        self.sensor_id = sensor_id
        self.host_hint = host_hint

    def collect(self) -> List[RawEventEnvelope]:
        records = json.loads(self.path.read_text(encoding="utf-8"))
        return [self.parse(record) for record in records]

    def parse(self, record: Dict[str, Any]) -> RawEventEnvelope:
        channel = str(record.get("channel") or "Security")
        event_id = int(record["event_id"])
        source_kind = "sysmon" if channel.lower().startswith("sysmon") or event_id in {1, 3, 5, 8, 10, 11, 12, 13, 14, 15, 22, 23, 25, 26} else "windows_security"
        dataset = "sysmon.operational" if source_kind == "sysmon" else "windows.security"
        source = SourceDescriptor(
            kind=source_kind,
            product="Microsoft Windows",
            dataset=dataset,
            sensor_id=str(record.get("sensor_id") or self.sensor_id),
            host_hint=str(record.get("computer") or self.host_hint),
            source_record_id=str(record.get("record_id") or event_id),
        )
        event_time = record.get("time_created") or record.get("event_time")
        return envelope_from_payload(
            source=source,
            payload=self._to_windows_xml(record),
            payload_format="xml",
            event_time_raw=event_time,
            raw_ref="file://%s#%s" % (self.path.as_posix(), source.source_record_id),
            observed_time=parse_timestamp(event_time) if event_time else None,
            labels={"collector": self.name, "event_id": event_id, "channel": channel},
        )

    def _to_windows_xml(self, record: Dict[str, Any]) -> str:
        event_data = record.get("event_data") or {}
        provider = html.escape(str(record.get("provider") or "Microsoft-Windows-Security-Auditing"))
        event_id = html.escape(str(record["event_id"]))
        record_id = html.escape(str(record.get("record_id") or event_id))
        computer = html.escape(str(record.get("computer") or self.host_hint))
        system_time = html.escape(str(record.get("time_created") or record.get("event_time") or ""))
        data = "".join('<Data Name="%s">%s</Data>' % (html.escape(str(key)), html.escape(str(value))) for key, value in event_data.items())
        return (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><Provider Name=\"%s\"/><EventID>%s</EventID><TimeCreated SystemTime=\"%s\"/>"
            "<EventRecordID>%s</EventRecordID><Computer>%s</Computer></System>"
            "<EventData>%s</EventData></Event>"
        ) % (provider, event_id, system_time, record_id, computer, data)
