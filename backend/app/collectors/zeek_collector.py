from pathlib import Path
from typing import Any, Dict, List

from app.collectors.base import BaseCollector, non_empty_lines
from app.collectors.envelope import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.time import parse_timestamp


class ZeekCollector(BaseCollector):
    name = "zeek"

    def __init__(self, root: Path, sensor_id: str = "zeek-core", host_hint: str = "network-sensor") -> None:
        self.root = Path(root)
        self.sensor_id = sensor_id
        self.host_hint = host_hint
        self.files = {"conn.log": "zeek.conn", "dns.log": "zeek.dns", "http.log": "zeek.http"}

    def collect(self) -> List[RawEventEnvelope]:
        envelopes: List[RawEventEnvelope] = []
        for file_name, dataset in self.files.items():
            path = self.root / file_name
            if not path.exists():
                continue
            for index, record in enumerate(self._read_zeek_log(path)):
                record["_dataset"] = dataset
                record["_record_id"] = "%s-%d" % (path.stem, index)
                record["_path"] = path
                envelopes.append(self.parse(record))
        if not envelopes and not self.root.exists():
            raise FileNotFoundError(str(self.root))
        return envelopes

    def parse(self, record: Dict[str, Any]) -> RawEventEnvelope:
        dataset = str(record.pop("_dataset"))
        record_id = str(record.pop("_record_id"))
        path = Path(record.pop("_path"))
        source = SourceDescriptor(
            kind="zeek",
            product="Zeek",
            dataset=dataset,
            sensor_id=self.sensor_id,
            host_hint=self.host_hint,
            source_record_id=record_id,
        )
        event_time = record.get("ts")
        return envelope_from_payload(
            source=source,
            payload=record,
            payload_format="json",
            event_time_raw=event_time,
            raw_ref="file://%s#%s" % (path.as_posix(), record_id),
            observed_time=parse_timestamp(event_time) if event_time else None,
            labels={"collector": self.name},
        )

    def _read_zeek_log(self, path: Path) -> List[Dict[str, Any]]:
        lines = path.read_text(encoding="utf-8").splitlines()
        fields: list[str] | None = None
        rows: List[Dict[str, Any]] = []
        for line in lines:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#"):
                continue
            values = line.split("\t")
            if fields:
                rows.append({field: self._coerce(value) for field, value in zip(fields, values)})
        if rows:
            return rows
        return [self._parse_jsonish(line) for line in non_empty_lines(lines)]

    def _coerce(self, value: str) -> Any:
        if value in {"-", "(empty)"}:
            return None
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value

    def _parse_jsonish(self, line: str) -> Dict[str, Any]:
        import json
        return json.loads(line)
