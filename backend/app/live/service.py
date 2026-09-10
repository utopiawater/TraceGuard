import json
from pathlib import Path
from typing import Iterable, List, Optional

from app.bootstrap import build_pipeline
from app.contracts import RawEventEnvelope
from app.core.ids import stable_id
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
        current = self.repository.current_live_run()
        if current:
            return self.status(current["run_id"])
        run_id = "live_%s_%s" % (utc_now().strftime("%Y%m%d_%H%M%S"), stable_id("run", utc_now().isoformat()).split("_", 1)[1][:8])
        manifest = {"source": "live", "raw_ids": [], "started_by": "api", "replay_path": replay_path or self.settings.live_replay_path or None}
        build_pipeline(self.settings, self.repository, self.graph).start_live_run(run_id, manifest)
        for collector in self.collectors(replay_path):
            self.repository.upsert_live_source(collector.source_id, collector.source_type, "offline", last_error="waiting for first batch")
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
            self.repository.upsert_live_source(source_id, source_type, "online", count, seen, None)
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
        for collector in self.collectors(configured_replay):
            cursor = self.repository.get_checkpoint(collector.source_id)
            result = collector.poll_new_events(cursor, self.settings.live_micro_batch_size)
            self.repository.put_checkpoint(collector.source_id, collector.source_type, result.cursor)
            if result.envelopes:
                self.append(run["run_id"], result.envelopes)
                processed += len(result.envelopes)
            self.repository.upsert_live_source(
                collector.source_id,
                collector.source_type,
                "online" if result.online else "offline",
                0,
                max((item.observed_time.isoformat() for item in result.envelopes), default=None),
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
            "sources": self.repository.list_live_sources(),
            "counts": counts,
            "attack_chain_stages": len(chains[0].steps) if chains else 0,
        }

    def collectors(self, replay_path: Optional[str] = None) -> List:
        collectors: List = []
        batch = self.settings.live_micro_batch_size
        path = replay_path or self.settings.live_replay_path
        if path:
            collectors.append(ReplayLiveCollector(Path(path), batch_size=batch))
        if self.settings.wazuh_jsonl_paths:
            collectors.append(WazuhLiveCollector(_split_paths(self.settings.wazuh_jsonl_paths), batch_size=batch))
        if self.settings.zeek_log_roots:
            collectors.append(ZeekLiveCollector(_split_paths(self.settings.zeek_log_roots), batch_size=batch))
        return collectors


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
