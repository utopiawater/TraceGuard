import json
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

from app.collectors.base import BaseCollector
from app.collectors.envelope import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.time import parse_timestamp


class ReplayCollector(BaseCollector):
    name = "replay"

    def __init__(self, path: Path, delay_seconds: float = 0) -> None:
        self.path = Path(path)
        self.delay_seconds = delay_seconds

    def collect(self) -> List[RawEventEnvelope]:
        records = json.loads(self.path.read_text(encoding="utf-8"))
        items = records.get("records", records) if isinstance(records, dict) else records
        return [self.parse(record) for record in items]

    def stream(self) -> Iterator[RawEventEnvelope]:
        for envelope in self.collect():
            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)
            yield envelope

    def parse(self, record: Dict[str, Any]) -> RawEventEnvelope:
        source_data = record.get("source", {})
        payload = record.get("payload", {})
        source = SourceDescriptor(
            kind=source_data.get("kind", "dataset"),
            product=source_data.get("product", "Replay Dataset"),
            dataset=source_data.get("dataset", "sample_attack_dataset"),
            sensor_id=source_data.get("sensor_id", "replay"),
            host_hint=source_data.get("host_hint"),
            source_record_id=source_data.get("source_record_id") or record.get("id"),
        )
        event_time = record.get("event_time_raw")
        if event_time is None and isinstance(payload, dict):
            event_time = payload.get("ts")
        return envelope_from_payload(
            source=source,
            payload=payload,
            payload_format=record.get("payload_format", "json"),
            event_time_raw=event_time,
            raw_ref=record.get("raw_ref") or "file://%s#%s" % (self.path.as_posix(), source.source_record_id),
            observed_time=parse_timestamp(event_time) if event_time else None,
            labels={"collector": self.name, **record.get("labels", {})},
        )
