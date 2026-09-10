import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from app.collectors.envelope import envelope_from_payload
from app.collectors.replay_collector import ReplayCollector
from app.collectors.zeek_collector import ZeekCollector
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.contracts.common import SourceKind
from app.core.time import parse_timestamp, utc_now
from app.scenarios import load_scenario


@dataclass
class LivePollResult:
    envelopes: List[RawEventEnvelope] = field(default_factory=list)
    cursor: dict = field(default_factory=dict)
    online: bool = True
    last_error: Optional[str] = None


class ReplayLiveCollector:
    source_type = "replay"
    _records_cache: Dict[str, List[RawEventEnvelope]] = {}

    def __init__(self, path: Path, batch_size: int = 10, source_id: str = "replay-live", loader: Optional[Callable[[Path], List[RawEventEnvelope]]] = None, cache_key: Optional[str] = None) -> None:
        self.path = Path(path)
        self.batch_size = batch_size
        self.source_id = source_id
        self.loader = loader
        self.cache_key = cache_key

    def poll_new_events(self, cursor: Optional[dict] = None, max_records: Optional[int] = None) -> LivePollResult:
        if not self.path.exists():
            return LivePollResult(cursor=cursor or {}, online=False, last_error="configured evidence source is unavailable")
        try:
            records = self._records()
            index = int((cursor or {}).get("index", 0))
            limit = max_records or self.batch_size
            batch = records[index:index + limit]
            return LivePollResult(batch, {"index": index + len(batch)}, online=True)
        except Exception as exc:
            return LivePollResult(cursor=cursor or {}, online=False, last_error=str(exc))

    def _records(self) -> List[RawEventEnvelope]:
        if self.cache_key and self.cache_key in self._records_cache:
            return self._records_cache[self.cache_key]
        if self.loader:
            records = self.loader(self.path)
        elif self.path.is_dir():
            records = load_scenario(self.path)
        else:
            records = ReplayCollector(self.path).collect()
        records = self._sort_for_replay(records)
        if self.cache_key:
            self._records_cache[self.cache_key] = records
        return records

    @staticmethod
    def _sort_for_replay(records: List[RawEventEnvelope]) -> List[RawEventEnvelope]:
        if not records:
            return []
        first_seen: Dict[str, Any] = {}
        for record in records:
            key = _replay_source_key(record)
            first = first_seen.get(key)
            if first is None or record.observed_time < first:
                first_seen[key] = record.observed_time
        if len(first_seen) <= 1:
            return sorted(records, key=lambda item: item.observed_time)
        first_span = max(first_seen.values()) - min(first_seen.values())
        if first_span.total_seconds() < 3600:
            return sorted(records, key=lambda item: item.observed_time)
        return sorted(
            records,
            key=lambda item: (
                (item.observed_time - first_seen[_replay_source_key(item)]).total_seconds(),
                _replay_source_key(item),
                item.observed_time,
            ),
        )


def _replay_source_key(record: RawEventEnvelope) -> str:
    return "%s:%s:%s" % (
        record.source.kind.value,
        record.source.dataset,
        record.labels.get("source_id") or record.source.sensor_id or "",
    )


class _TailFileCollector:
    files: Dict[str, str]

    def _poll_files(self, cursor: Optional[dict], max_records: int) -> LivePollResult:
        state = dict(cursor or {})
        file_state = dict(state.get("files") or {})
        envelopes: List[RawEventEnvelope] = []
        errors: List[str] = []
        any_seen = False
        for path, dataset in self._candidate_files():
            key = str(path)
            current = dict(file_state.get(key) or {})
            offset = int(current.get("offset", 0) or 0)
            if not path.exists():
                errors.append("missing %s" % path)
                file_state[key] = {**current, "offset": offset}
                continue
            any_seen = True
            size = path.stat().st_size
            if size < offset:
                offset = 0
            try:
                batch, offset, extra = self._read_new_records(path, dataset, offset, max_records - len(envelopes), current)
                envelopes.extend(batch)
                file_state[key] = {**current, **extra, "offset": offset}
            except Exception as exc:
                errors.append("%s: %s" % (path, exc))
                file_state[key] = {**current, "offset": offset}
            if len(envelopes) >= max_records:
                break
        state["files"] = file_state
        return LivePollResult(envelopes=envelopes, cursor=state, online=any_seen, last_error="; ".join(errors) if errors else None)

    def _candidate_files(self) -> Iterable[tuple[Path, str]]:
        raise NotImplementedError

    def _read_new_records(self, path: Path, dataset: str, offset: int, max_records: int, state: dict) -> tuple[List[RawEventEnvelope], int, dict]:
        raise NotImplementedError


class WazuhLiveCollector(_TailFileCollector):
    source_type = "wazuh"

    def __init__(self, paths: Iterable[Path], batch_size: int = 100, source_id: str = "wazuh-manager") -> None:
        self.paths = [Path(path) for path in paths if str(path)]
        self.batch_size = batch_size
        self.source_id = source_id

    def poll_new_events(self, cursor: Optional[dict] = None, max_records: Optional[int] = None) -> LivePollResult:
        return self._poll_files(cursor, max_records or self.batch_size)

    def _candidate_files(self) -> Iterable[tuple[Path, str]]:
        for path in self.paths:
            yield path, "wazuh.alerts"

    def _read_new_records(self, path: Path, dataset: str, offset: int, max_records: int, state: dict) -> tuple[List[RawEventEnvelope], int, dict]:
        envelopes: List[RawEventEnvelope] = []
        with path.open("rb") as handle:
            handle.seek(offset)
            while len(envelopes) < max_records:
                start = handle.tell()
                raw_line = handle.readline()
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    handle.seek(start)
                    break
                line = raw_line.decode("utf-8", "replace").strip()
                if not line:
                    continue
                envelopes.append(self._envelope(path, start, line))
            return envelopes, handle.tell(), {}

    def _envelope(self, path: Path, offset: int, line: str) -> RawEventEnvelope:
        try:
            payload: Any = json.loads(line)
            payload_format = "json"
        except json.JSONDecodeError:
            payload = line
            payload_format = "text"
        agent = payload.get("agent") if isinstance(payload, dict) else {}
        timestamp = payload.get("timestamp") if isinstance(payload, dict) else None
        source = SourceDescriptor(
            kind=SourceKind.wazuh,
            product="Wazuh Manager",
            dataset="wazuh.alerts",
            sensor_id=str((agent or {}).get("id") or self.source_id),
            host_hint=(agent or {}).get("name"),
            source_record_id="%s:%d" % (path.name, offset),
        )
        observed = _parse_or_now(timestamp)
        return envelope_from_payload(source, payload, payload_format, timestamp, "%s#byte=%d" % (path.as_posix(), offset), observed, {"collector": "wazuh_live", "source_id": self.source_id})


class ZeekLiveCollector(_TailFileCollector):
    source_type = "zeek"

    def __init__(self, roots: Iterable[Path], batch_size: int = 100, source_id: str = "n3-zeek", host_hint: str = "N3-Zeek") -> None:
        self.roots = [Path(root) for root in roots if str(root)]
        self.batch_size = batch_size
        self.source_id = source_id
        self.host_hint = host_hint
        self.files = {"conn.log": "zeek.conn", "http.log": "zeek.http", "dns.log": "zeek.dns", "notice.log": "zeek.notice"}
        self._parser = ZeekCollector(Path("."))

    def poll_new_events(self, cursor: Optional[dict] = None, max_records: Optional[int] = None) -> LivePollResult:
        return self._poll_files(cursor, max_records or self.batch_size)

    def _candidate_files(self) -> Iterable[tuple[Path, str]]:
        for root in self.roots:
            for name, dataset in self.files.items():
                yield root / name, dataset

    def _read_new_records(self, path: Path, dataset: str, offset: int, max_records: int, state: dict) -> tuple[List[RawEventEnvelope], int, dict]:
        fields = state.get("fields")
        with path.open("rb") as handle:
            if not fields:
                fields = self._read_fields(handle, offset)
            handle.seek(offset)
            envelopes: List[RawEventEnvelope] = []
            while len(envelopes) < max_records:
                start = handle.tell()
                raw_line = handle.readline()
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    handle.seek(start)
                    break
                line = raw_line.decode("utf-8", "replace").strip()
                if not line or line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    continue
                record = self._parse_line(line, fields)
                record["_dataset"] = dataset
                envelopes.append(self._envelope(path, start, dataset, record))
            return envelopes, handle.tell(), {"fields": fields}

    def _read_fields(self, handle, offset: int) -> Optional[List[str]]:
        handle.seek(0)
        fields = None
        while handle.tell() <= offset:
            line = handle.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            if text.startswith("#fields"):
                fields = text.split("\t")[1:]
        return fields

    def _parse_line(self, line: str, fields: Optional[List[str]]) -> Dict[str, Any]:
        if line.startswith("{"):
            return json.loads(line)
        if not fields:
            return {"_parse_error": "missing zeek #fields header", "raw": line}
        return {field: self._parser._coerce(value) for field, value in zip(fields, line.split("\t"))}

    def _envelope(self, path: Path, offset: int, dataset: str, record: Dict[str, Any]) -> RawEventEnvelope:
        timestamp = record.get("ts")
        source = SourceDescriptor(
            kind=SourceKind.zeek,
            product="Zeek",
            dataset=dataset,
            sensor_id=self.source_id,
            host_hint=self.host_hint,
            source_record_id="%s:%d" % (path.name, offset),
        )
        return envelope_from_payload(source, record, "json", timestamp, "%s#byte=%d" % (path.as_posix(), offset), _parse_or_now(timestamp), {"collector": "zeek_live", "source_id": self.source_id})


def _parse_or_now(value: Any):
    if value is None:
        return utc_now()
    try:
        return parse_timestamp(value)
    except (TypeError, ValueError):
        return utc_now()
