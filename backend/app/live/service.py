import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable, List, Optional

from app.analysis import AnalysisTaskService
from app.bootstrap import build_pipeline
from app.contracts import RawEventEnvelope
from app.core.ids import sha256_text, stable_id
from app.core.settings import Settings
from app.core.time import utc_now
from app.graph.ports import GraphProjector
from app.ingestion.pipeline import PipelineResult
from app.live.collectors import ReplayLiveCollector, WazuhLiveCollector, ZeekLiveCollector
from app.repositories import SQLiteRepository


class LiveRunService:
    version = "1.0.0"

    def __init__(self, settings: Settings, repository: SQLiteRepository, graph: GraphProjector) -> None:
        self.settings = settings
        self.repository = repository
        self.graph = graph

    def start(self, replay_path: Optional[str] = None) -> dict:
        now = utc_now()
        run_id = "live_%s_%s" % (now.strftime("%Y%m%d_%H%M%S"), stable_id("run", now.isoformat()).split("_", 1)[1][:8])
        configured_replay = self._configured_replay_path(replay_path)
        source = "demo_replay" if configured_replay else "live"
        manifest = {
            "source": source,
            "raw_ids": [],
            "started_by": "api",
            "replay_path": configured_replay,
            "replay_clock": {"time_compression": self._time_compression()},
        }
        build_pipeline(self.settings, self.repository, self.graph).start_live_run(run_id, manifest)
        for collector in self.collectors(configured_replay, run_id):
            self.repository.upsert_live_source(run_id, collector.source_id, collector.source_type, "offline", last_error="waiting for first batch")
        return self.status(run_id)

    def append(self, run_id: str, envelopes: List[RawEventEnvelope]) -> PipelineResult:
        result = build_pipeline(self.settings, self.repository, self.graph).append_live_batch(run_id, envelopes)
        by_source: dict[str, tuple[str, int, str]] = {}
        for raw in envelopes:
            source_id = str(raw.labels.get("source_id") or raw.source.sensor_id)
            source_type = raw.source.kind.value
            previous = by_source.get(source_id, (source_type, 0, raw.observed_time.isoformat()))
            by_source[source_id] = (source_type, previous[1] + 1, max(previous[2], raw.observed_time.isoformat()))
        for source_id, (source_type, count, seen) in by_source.items():
            self.repository.upsert_live_source(run_id, source_id, source_type, "online", count, seen, None)
        return result

    def stop(self, run_id: str) -> dict:
        run = self.repository.get_run(run_id)
        if not run:
            raise KeyError(run_id)
        build_pipeline(self.settings, self.repository, self.graph).stop_live_run(run_id)
        return self.status(run_id)

    def poll_once(self, run_id: Optional[str] = None, replay_path: Optional[str] = None) -> int:
        run = self.repository.get_run(run_id) if run_id else self.repository.current_live_run()
        if not run or run.get("status") != "running" or run.get("mode") != "live":
            return 0
        processed = 0
        configured_replay = replay_path or _manifest_value(run, "replay_path")
        for collector in self.collectors(configured_replay, run["run_id"]):
            cursor = self.repository.get_checkpoint(run["run_id"], collector.source_id)
            result = collector.poll_new_events(cursor, self.settings.live_micro_batch_size)
            envelopes = self._prepare_live_batch(run, collector.source_type, result.envelopes)
            self.repository.put_checkpoint(run["run_id"], collector.source_id, collector.source_type, result.cursor)
            if envelopes:
                self.append(run["run_id"], envelopes)
                processed += len(envelopes)
            self.repository.upsert_live_source(
                run["run_id"],
                collector.source_id,
                collector.source_type,
                "online" if result.online else "offline",
                0,
                max((item.observed_time.isoformat() for item in envelopes), default=None),
                result.last_error,
            )
        return processed

    def status(self, run_id: Optional[str] = None) -> dict:
        run = self.repository.get_run(run_id) if run_id else self.repository.current_live_run()
        counts = self.repository.counts(run_id=run["run_id"]) if run else {}
        chains = self.repository.list_chains(1, run_id=run["run_id"]) if run else []
        return {
            "run_id": run["run_id"] if run else None,
            "mode": run.get("mode") if run else "live",
            "status": run.get("status") if run else "idle",
            "started_at": run.get("started_at") if run else None,
            "completed_at": run.get("completed_at") if run else None,
            "sources": self.repository.list_live_sources(run["run_id"]) if run else [],
            "counts": counts,
            "attack_chain_stages": len(chains[0].steps) if chains else 0,
        }

    def collectors(self, replay_path: Optional[str] = None, run_id: Optional[str] = None) -> List:
        collectors: List = []
        batch = self.settings.live_micro_batch_size
        path = self._configured_replay_path(replay_path)
        if path:
            source_path = Path(path)
            loader = self._bundle_loader(run_id) if self._needs_bundle_parser(source_path) and run_id else None
            cache_key = "%s:%s" % (run_id or "global", source_path.resolve() if source_path.exists() else source_path)
            collectors.append(ReplayLiveCollector(source_path, batch_size=batch, loader=loader, cache_key=cache_key))
        if self.settings.wazuh_jsonl_paths:
            collectors.append(WazuhLiveCollector(_split_paths(self.settings.wazuh_jsonl_paths), batch_size=batch))
        if self.settings.zeek_log_roots:
            collectors.append(ZeekLiveCollector(_split_paths(self.settings.zeek_log_roots), batch_size=batch))
        return collectors

    def _configured_replay_path(self, replay_path: Optional[str] = None) -> Optional[str]:
        return replay_path or self.settings.demo_bundle_path or self.settings.live_replay_path or None

    def _bundle_loader(self, run_id: Optional[str]):
        task_id = "live_replay_%s" % (run_id or stable_id("live_replay", utc_now().isoformat()).split("_", 1)[1][:8])

        def load(path: Path) -> List[RawEventEnvelope]:
            return AnalysisTaskService(self.settings, self.repository, self.graph).raw_envelopes_from_bundle(path, task_id)

        return load

    @staticmethod
    def _needs_bundle_parser(path: Path) -> bool:
        if path.is_dir():
            return False
        name = path.name.lower()
        if name.endswith(".tar.gz"):
            return True
        return path.suffix.lower() != ".json"

    def _prepare_live_batch(self, run: dict, source_type: str, envelopes: List[RawEventEnvelope]) -> List[RawEventEnvelope]:
        if source_type != "replay" or not envelopes:
            return envelopes
        run_id = run["run_id"]
        replayed = self._apply_replay_clock(envelopes)
        return [self._run_scoped_raw(run_id, raw) for raw in replayed]

    def _apply_replay_clock(self, envelopes: List[RawEventEnvelope]) -> List[RawEventEnvelope]:
        now = utc_now()
        newest_original = max(item.observed_time for item in envelopes)
        compression = self._time_compression()
        mapped: List[RawEventEnvelope] = []
        for raw in envelopes:
            lag = min(max((newest_original - raw.observed_time).total_seconds() / compression, 0), 85)
            replay_time = now - timedelta(seconds=lag)
            labels = {
                **raw.labels,
                "original_event_time": raw.event_time_raw if raw.event_time_raw is not None else raw.observed_time.isoformat(),
                "original_payload_time": self._payload_time(raw.payload),
                "replay_arrived_at": now.isoformat(),
                "replay_clock": "compressed_current_time",
                "replay_time_compression": compression,
            }
            payload = self._payload_with_replay_time(raw.payload, replay_time)
            mapped.append(raw.model_copy(update={"event_time_raw": replay_time.isoformat(), "observed_time": replay_time, "ingested_time": now, "payload": payload, "raw_sha256": self._payload_digest(payload), "labels": labels}))
        return mapped

    def _run_scoped_raw(self, run_id: str, raw: RawEventEnvelope) -> RawEventEnvelope:
        source_record_id = "%s:%s" % (run_id, raw.source_record_id or raw.raw_id)
        source = raw.source.model_copy(update={"source_record_id": source_record_id})
        original_ref = raw.raw_ref
        labels = {
            **raw.labels,
            "source_id": raw.labels.get("source_id") or raw.source.sensor_id,
            "replay_run_id": run_id,
            "original_raw_id": raw.raw_id,
            "original_raw_ref": original_ref,
            "original_raw_sha256": raw.raw_sha256,
        }
        scoped_id = stable_id("raw", run_id, raw.raw_id)
        return raw.model_copy(update={"raw_id": scoped_id, "source": source, "source_record_id": source_record_id, "raw_ref": "replay://%s/%s" % (run_id, original_ref), "labels": labels})

    def _time_compression(self) -> float:
        return max(float(getattr(self.settings, "demo_replay_time_compression", 60) or 60), 1.0)

    @staticmethod
    def _payload_time(payload: Any) -> Optional[Any]:
        if isinstance(payload, dict):
            return payload.get("timestamp") or payload.get("ts") or payload.get("UtcTime") or payload.get("time")
        return None

    @staticmethod
    def _payload_with_replay_time(payload: Any, replay_time) -> Any:
        if isinstance(payload, dict):
            updated = dict(payload)
            for key in ("timestamp", "UtcTime", "time"):
                if key in updated:
                    updated[key] = replay_time.isoformat()
            if "ts" in updated:
                updated["ts"] = replay_time.timestamp()
            return updated
        if isinstance(payload, str) and "<Event" in payload and "TimeCreated" in payload:
            replacement = "SystemTime='%s'" % replay_time.isoformat().replace("+00:00", "Z")
            updated = re.sub(r"SystemTime=['\"][^'\"]+['\"]", replacement, payload, count=1)
            text_time = replay_time.isoformat().replace("+00:00", "Z")
            updated = re.sub(r"(<Data\s+Name=['\"]UtcTime['\"]>)(.*?)(</Data>)", r"\g<1>%s\g<3>" % text_time, updated, count=1, flags=re.S)
            return updated
        return payload

    @staticmethod
    def _payload_digest(payload: Any) -> str:
        canonical = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return sha256_text(canonical)


def _split_paths(value: str) -> Iterable[Path]:
    for item in value.split(";"):
        stripped = item.strip()
        if stripped:
            yield Path(stripped)


def _manifest_value(run: Optional[dict], key: str) -> Optional[str]:
    if not run:
        return None
    try:
        manifest = json.loads(run.get("input_manifest_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    value = manifest.get(key)
    return str(value) if value else None
