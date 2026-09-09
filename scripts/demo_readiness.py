import argparse
import importlib.metadata
import json
import sqlite3
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def add(checks: list[dict], name: str, ok: bool, detail: object, required: bool = True) -> None:
    checks.append({"name": name, "ok": bool(ok), "required": required, "detail": detail})


def http_get_json(url: str, timeout: float = 4.0) -> tuple[bool, object]:
    try:
        import httpx

        with httpx.Client(trust_env=False, timeout=timeout) as client:
            response = client.get(url)
        if response.status_code != 200:
            return False, {"status_code": response.status_code}
        return True, response.json()
    except Exception as exc:
        return False, {"error_type": type(exc).__name__, "message": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceGuard demo readiness check")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--frontend-url", default="http://127.0.0.1:5173")
    parser.add_argument("--require-services", action="store_true", help="Fail when FastAPI or frontend is not reachable.")
    parser.add_argument("--require-real-llm", action="store_true", help="Fail when real LLM configuration is incomplete.")
    args = parser.parse_args()

    from app.agents.harness import EvidenceValidator
    from app.contracts import AgentResult
    from app.core.settings import settings

    checks: list[dict] = []
    add(
        checks,
        "python_runtime",
        sys.version_info[:2] == (3, 13) and ssl.OPENSSL_VERSION_INFO >= (3, 0),
        {"version": ".".join(str(item) for item in sys.version_info[:3]), "openssl": ssl.OPENSSL_VERSION},
    )

    required_packages = ["fastapi", "uvicorn", "pydantic", "neo4j", "httpx", "python-dotenv", "jsonschema"]
    missing = []
    versions = {}
    for package in required_packages:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            missing.append(package)
    add(checks, "python_dependencies", not missing, {"installed": versions, "missing": missing})

    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", ".env"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    add(checks, "env_file", (ROOT / ".env").is_file() and ignored, {"exists": (ROOT / ".env").is_file(), "git_ignored": ignored})

    llm_configured = bool(settings.llm_base_url and settings.llm_api_key and settings.llm_model)
    add(
        checks,
        "llm_configuration",
        llm_configured,
        {
            "configured": llm_configured,
            "execution_mode": "real_llm" if llm_configured else "deterministic_fallback",
            "provider_host": urlparse(settings.llm_base_url).hostname if settings.llm_base_url else None,
            "model": settings.llm_model or None,
            "timeout_seconds": settings.llm_timeout_seconds,
            "api_key_configured": bool(settings.llm_api_key),
        },
        required=args.require_real_llm,
    )

    db_path = settings.database_path
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    db_ready = db_path.is_file()
    db_detail: dict[str, object] = {"path": str(db_path), "exists": db_ready}
    if db_ready:
        try:
            with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as connection:
                connection.execute("SELECT 1").fetchone()
                tables = ["raw_events", "normalized_events", "sessions", "detections", "evidence", "attack_chains", "agent_results"]
                counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
                chains = [json.loads(row[0]) for row in connection.execute("SELECT chain_json FROM attack_chains LIMIT 20").fetchall()]
                evidence_ids = {row[0] for row in connection.execute("SELECT evidence_id FROM evidence").fetchall()}
                chain_errors = []
                for chain in chains:
                    for step in chain.get("steps", []):
                        missing_step_evidence = [item for item in step.get("evidence_ids", []) if item not in evidence_ids]
                        if missing_step_evidence:
                            chain_errors.append({"chain_id": chain.get("chain_id"), "step_id": step.get("step_id"), "missing_evidence": missing_step_evidence})
            db_detail.update({
                "counts": counts,
                "chain_count": len(chains),
                "evidence_count": len(evidence_ids),
                "chain_evidence_errors": chain_errors,
                "prepare_demo_command": "py -3.13 scripts/replay_scenario.py --scenario backend/fixtures/scenarios/full_attack_chain --run-id run_full_multisource_001",
            })
            db_ready = counts.get("normalized_events", 0) > 0 and len(chains) > 0 and len(evidence_ids) > 0 and not chain_errors
        except Exception as exc:
            db_ready = False
            db_detail.update({"error_type": type(exc).__name__, "message": str(exc)})
    else:
        db_detail["prepare_demo_command"] = "py -3.13 scripts/replay_scenario.py --scenario backend/fixtures/scenarios/full_attack_chain --run-id run_full_multisource_001"
    add(checks, "sqlite_demo_data", db_ready, db_detail)

    api_ok, api_payload = http_get_json(f"{args.api_url.rstrip('/')}/api/system/health")
    add(checks, "fastapi_service", api_ok and isinstance(api_payload, dict) and api_payload.get("data", {}).get("status") == "ok", {"url": args.api_url, "response": api_payload}, required=args.require_services)

    frontend_ok, frontend_detail = http_get_json(args.frontend_url, timeout=3)
    if not frontend_ok and isinstance(frontend_detail, dict) and frontend_detail.get("error_type"):
        try:
            import httpx

            with httpx.Client(trust_env=False, timeout=3) as client:
                page = client.get(args.frontend_url)
            frontend_ok = page.status_code == 200
            frontend_detail = {"url": args.frontend_url, "status_code": page.status_code}
        except Exception as exc:
            frontend_detail = {"url": args.frontend_url, "error_type": type(exc).__name__, "message": str(exc)}
    add(checks, "frontend_service", frontend_ok, frontend_detail, required=args.require_services)

    graph_detail = {"source": "settings", "configured": settings.neo4j_enabled}
    graph_ok = False
    if api_ok and isinstance(api_payload, dict):
        graph = api_payload.get("data", {}).get("graph", {})
        graph_ok = bool(graph.get("connected"))
        graph_detail = {"source": "api_health", **graph}
    add(checks, "neo4j_runtime", graph_ok, graph_detail, required=args.require_services and settings.neo4j_enabled)

    release_dir = ROOT / "artifacts" / "release"
    release_files = sorted(item.name for item in release_dir.glob("*") if item.is_file()) if release_dir.exists() else []
    add(
        checks,
        "release_snapshot",
        any(name.endswith(".acceptance.json") for name in release_files) and any(name.endswith(".html") for name in release_files),
        {"path": str(release_dir), "files": release_files},
        required=False,
    )

    if db_ready:
        try:
            validator = EvidenceValidator()
            with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as connection:
                evidence_ids = {row[0] for row in connection.execute("SELECT evidence_id FROM evidence").fetchall()}
                records = [json.loads(row[0]) for row in connection.execute("SELECT result_json FROM agent_results LIMIT 5000").fetchall()]
            errors = []
            for record in records:
                result = AgentResult.model_validate(record["result"])
                errors.extend(validator.validate(result, evidence_ids))
            add(checks, "agent_evidence_validator", not errors, {"checked_records": len(records), "errors": errors}, required=False)
        except Exception as exc:
            add(checks, "agent_evidence_validator", False, {"error_type": type(exc).__name__, "message": str(exc)}, required=False)

    failed_required = [item for item in checks if item["required"] and not item["ok"]]
    output = {
        "status": "passed" if not failed_required else "failed",
        "summary": {
            "required_failed": [item["name"] for item in failed_required],
            "warnings": [item["name"] for item in checks if not item["required"] and not item["ok"]],
        },
        "checks": checks,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
