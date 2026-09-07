import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.bootstrap import build_pipeline
from app.core.settings import Settings
from app.scenarios import load_scenario


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a versioned scenario through the final analysis pipeline")
    parser.add_argument("--scenario", default=str(ROOT / "backend" / "fixtures" / "scenarios" / "powershell_cross_source"))
    parser.add_argument("--data-dir", default=str(ROOT / "data"))
    parser.add_argument("--run-id", default="run_powershell_cross_source_001")
    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    settings = Settings(data_dir=data_dir, database_path=data_dir / "traceguard.db", raw_archive_dir=data_dir / "raw", mode="replay")
    pipeline = build_pipeline(settings)
    result = pipeline.run(args.run_id, load_scenario(Path(args.scenario)), mode="replay")
    print(json.dumps({
        "run_id": result.run_id, "accepted_raw": result.accepted_raw, "events": len(result.events),
        "sessions": len(result.sessions), "detections": len(result.detections), "chains": len(result.chains),
        "techniques": result.chains[0].technique_ids if result.chains else [],
        "stored_totals": pipeline.repository.counts(),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
