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


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceGuard release environment check")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--frontend-url", default="http://127.0.0.1:5173")
    args = parser.parse_args()

    from app.core.settings import settings

    checks = []

    def add(name: str, ok: bool, detail: object) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add(
        "python",
        sys.version_info[:2] == (3, 13) and ssl.OPENSSL_VERSION_INFO >= (3, 0),
        {"version": platform_version(), "openssl": ssl.OPENSSL_VERSION},
    )

    required = ["fastapi", "uvicorn", "pydantic", "neo4j", "httpx", "python-dotenv", "jsonschema"]
    installed = {}
    missing = []
    for package in required:
        try:
            installed[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            missing.append(package)
    add("python_dependencies", not missing, {"installed": installed, "missing": missing})

    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", ".env"], cwd=ROOT, check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    add("env_file", (ROOT / ".env").is_file() and ignored, {"path": ".env", "git_ignored": ignored})
    llm_configured = bool(settings.llm_base_url and settings.llm_api_key and settings.llm_model)
    provider_host = urlparse(settings.llm_base_url).hostname if settings.llm_base_url else None
    add(
        "llm_configuration",
        llm_configured and settings.llm_timeout_seconds >= 180,
        {
            "configured": llm_configured,
            "execution_mode": "real_llm" if llm_configured else "deterministic_fallback",
            "provider_host": provider_host,
            "model": settings.llm_model or None,
            "timeout_seconds": settings.llm_timeout_seconds,
            "api_key_configured": bool(settings.llm_api_key),
        },
    )

    try:
        with sqlite3.connect(settings.database_path) as connection:
            connection.execute("SELECT 1").fetchone()
        add("sqlite", True, {"path": str(settings.database_path), "accessible": True})
    except Exception as exc:
        add("sqlite", False, {"path": str(settings.database_path), "error_type": type(exc).__name__})

    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=3,
        )
        driver.verify_connectivity()
        driver.close()
        add("neo4j", True, {"online": True})
    except Exception as exc:
        add("neo4j", False, {"online": False, "error_type": type(exc).__name__})

    try:
        import httpx

        with httpx.Client(trust_env=False, timeout=5) as local_client:
            api = local_client.get(f"{args.api_url.rstrip('/')}/api/system/health")
        api_ok = api.status_code == 200 and api.json().get("data", {}).get("status") == "ok"
        add("fastapi", api_ok, {"url": args.api_url, "status_code": api.status_code})
    except Exception as exc:
        add("fastapi", False, {"url": args.api_url, "error_type": type(exc).__name__})

    try:
        import httpx

        with httpx.Client(trust_env=False, timeout=5) as local_client:
            frontend = local_client.get(args.frontend_url)
        add("frontend", frontend.status_code == 200, {"url": args.frontend_url, "status_code": frontend.status_code})
    except Exception as exc:
        add("frontend", False, {"url": args.frontend_url, "error_type": type(exc).__name__})

    if llm_configured:
        try:
            import httpx

            models = httpx.get(
                f"{settings.llm_base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                timeout=min(settings.llm_timeout_seconds, 15),
            )
            add("llm_reachability", models.status_code == 200, {"reachable": models.status_code == 200, "status_code": models.status_code})
        except Exception as exc:
            add("llm_reachability", False, {"reachable": False, "error_type": type(exc).__name__})
    else:
        add("llm_reachability", False, {"reachable": False, "reason": "configuration_incomplete"})

    output = {"status": "passed" if all(item["ok"] for item in checks) else "failed", "checks": checks}
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output["status"] == "passed" else 1


def platform_version() -> str:
    return ".".join(str(item) for item in sys.version_info[:3])


if __name__ == "__main__":
    raise SystemExit(main())
