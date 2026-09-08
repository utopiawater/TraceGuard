import hashlib
import json
import sys
import tempfile
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.bootstrap import build_pipeline
from app.contracts import AgentResult
from app.core.settings import Settings, settings
from app.graph import InMemoryGraphProjector
from app.repositories import SQLiteRepository
from app.scenarios import load_scenario
from app.agents.harness import EvidenceValidator


CASE_ID = "case_1421c3d00365403d"
CHAIN_ID = "chain_0cf169837ae6850e2e88344d"
EXPECTED_STAGES = [
    "initial_access", "execution", "command_and_control", "lateral_movement",
    "privilege_escalation", "collection", "exfiltration",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def main() -> int:
    checks = []
    with tempfile.TemporaryDirectory(prefix="traceguard-release-") as temporary:
        data = Path(temporary)
        replay_settings = Settings(
            data_dir=data,
            database_path=data / "release.db",
            raw_archive_dir=data / "raw",
            report_dir=data / "reports",
            neo4j_enabled=False,
            llm_base_url="",
            llm_api_key="",
            llm_model="",
        )
        replay_repo = SQLiteRepository(replay_settings.database_path)
        replay = build_pipeline(replay_settings, replay_repo, InMemoryGraphProjector()).run(
            "run_release_verify",
            load_scenario(ROOT / "backend" / "fixtures" / "scenarios" / "full_attack_chain"),
        )
        require(replay.accepted_raw > 0, "raw events were not accepted")
        require(len(replay.events) > 0, "no unified events were produced")
        require(replay_repo.counts()["raw_events"] == replay.accepted_raw, "SQLite did not persist accepted raw events")
        require(replay_repo.counts()["normalized_events"] == len(replay.events), "SQLite did not persist unified events")
        require(len(replay.chains) == 1, "expected one deterministic attack chain")
        require([step.stage for step in replay.chains[0].steps] == EXPECTED_STAGES, "seven-stage chain changed")
        require(all(step.evidence_ids for step in replay.chains[0].steps), "attack chain step lacks evidence")
        checks.append("Raw Event → Unified Event → SQLite → Detection → ATT&CK → seven-stage AttackChain")

    live_repo = SQLiteRepository(settings.database_path)
    chain = live_repo.get_chain(CHAIN_ID)
    require(chain is not None, "formal seven-stage chain is missing")
    records = [item for item in live_repo.list_agent_records(5000) if item["task"]["case_id"] == CASE_ID]
    require(len(records) == 6, "formal real-LLM case does not contain six Agent tasks")
    require(all(item["result"]["result"]["status"] == "succeeded" for item in records), "an Agent task is not succeeded")
    require(all(item["result"]["runtime"]["fallback"] is False for item in records), "formal case contains fallback")
    require({item["result"]["result"]["model_info"]["model"] for item in records} == {"deepseek-v4-flash"}, "formal case model changed")
    require(sum(len(item["result"]["result"]["tool_calls"]) for item in records) == 22, "tool-call count changed")
    require(sum(len(item["result"]["result"]["findings"]) for item in records) == 55, "finding count changed")
    evidence_ids = {item.evidence_id for item in live_repo.list_evidence(10000)}
    referenced = {
        evidence_id
        for item in records
        for finding in item["result"]["result"]["findings"]
        for evidence_id in finding["evidence_ids"]
    }
    require(len(referenced) == 26 and referenced <= evidence_ids, "formal case Evidence set is invalid")
    validator = EvidenceValidator()
    require(all(not validator.validate(AgentResult.model_validate(item["result"]["result"]), evidence_ids) for item in records), "EvidenceValidator rejected the formal case")
    require(sum(item["runtime"].get("token_usage", {}).get("total_tokens", 0) for item in records) == 153253, "token usage changed")
    checks.append("DeepSeek six-Agent case → EvidenceValidator → Attribution → Report")

    acceptance = json.loads((ROOT / "artifacts" / "release" / f"{CASE_ID}.acceptance.json").read_text(encoding="utf-8"))
    for report in acceptance["reports"]:
        path = ROOT / "artifacts" / "release" / report["artifact"]
        require(path.is_file() and sha256(path) == report["sha256"], "archived report integrity check failed")
    checks.append("formal acceptance metadata and archived report integrity")

    with httpx.Client(trust_env=False, timeout=10) as local_client:
        api = local_client.get("http://127.0.0.1:8000/api/system/health")
        require(api.status_code == 200, "FastAPI is unavailable on release port 8000")
        health = api.json()["data"]
        require(health["graph"]["connected"] is True, "Neo4j runtime is not connected")
        frontend = local_client.get("http://127.0.0.1:5173")
        require(frontend.status_code == 200, "frontend is unavailable on release port 5173")
    checks.append("Neo4j runtime → FastAPI → Frontend")

    print(json.dumps({"status": "passed", "case_id": CASE_ID, "checks": checks}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
