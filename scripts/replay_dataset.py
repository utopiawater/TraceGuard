import argparse
import json
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.agents.service import InvestigationService
from app.bootstrap import build_pipeline
from app.core.settings import Settings
from app.datasets import build_dataset_run_report, inspect_dataset, load_raw_envelopes, write_dataset_run_report
from app.graph import InMemoryGraphProjector
from app.repositories import SQLiteRepository


def _safe_reset(path: Path) -> None:
    resolved = path.resolve()
    root = PROJECT_ROOT.resolve()
    if resolved == root or root not in resolved.parents:
        raise ValueError("refusing to reset path outside project root: %s" % resolved)
    if resolved.exists():
        shutil.rmtree(resolved)


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DARPA TC E3 CADets through the TraceGuard analysis pipeline.")
    parser.add_argument("--dataset", type=Path, default=PROJECT_ROOT / "datasets" / "darpa_tc_e3_cadets")
    parser.add_argument("--data-dir", type=Path, default=PROJECT_ROOT / "data" / "dataset_e3")
    parser.add_argument("--run-id", default="run_darpa_tc_e3_001")
    parser.add_argument("--reset", action="store_true", help="Delete only the selected data directory before running.")
    parser.add_argument("--quick-investigation", action="store_true", help="Run a quick four-agent investigation for the first generated chain.")
    parser.add_argument("--agent-fallback", action="store_true", help="Use deterministic Agent fallback instead of any configured LLM.")
    args = parser.parse_args()

    dataset_root = args.dataset.resolve()
    data_dir = args.data_dir.resolve()
    if args.reset:
        _safe_reset(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    inspection = inspect_dataset(dataset_root)
    raws = load_raw_envelopes(dataset_root)
    settings_kwargs = {
        "data_dir": data_dir,
        "database_path": data_dir / "traceguard.db",
        "raw_archive_dir": data_dir / "raw",
        "report_dir": data_dir / "reports",
        "neo4j_enabled": False,
    }
    if args.agent_fallback:
        settings_kwargs.update({"llm_base_url": "", "llm_api_key": "", "llm_model": ""})
    settings = Settings(**settings_kwargs)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    pipeline = build_pipeline(settings, repo, graph)

    started = time.perf_counter()
    result = pipeline.run(args.run_id, raws, mode="replay")
    runtime = time.perf_counter() - started

    report = build_dataset_run_report(dataset_root, args.run_id, result, repo, runtime, None)
    report["inspection"] = inspection
    report_path = write_dataset_run_report(report, data_dir)

    if args.quick_investigation and result.chains:
        service = InvestigationService(repo, graph, settings)
        report["multi_agent"] = service.investigate(result.chains[0].chain_id, scope="quick", max_steps=4)
        report_path = write_dataset_run_report(report, data_dir)
    print(json.dumps({
        "dataset_id": report["dataset_id"],
        "dataset_name": report["dataset_name"],
        "run_id": report["run_id"],
        "input_records": report["input_records"],
        "accepted_raw": report["accepted_raw"],
        "normalized_records": report["normalized_records"],
        "failed_records": report["failed_records"],
        "mapping_rate": report["mapping_rate"],
        "unknown_action_count": report["unknown_action_count"],
        "entity_count": report["entity_count"],
        "session_count": report["session_count"],
        "detection_count": report["detection_count"],
        "evidence_count": report["evidence_count"],
        "attack_technique_ids": report["attack_technique_ids"],
        "attack_chain_count": report["attack_chain_count"],
        "runtime_seconds": report["runtime_seconds"],
        "events_per_second": report["events_per_second"],
        "report_path": str(report_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
