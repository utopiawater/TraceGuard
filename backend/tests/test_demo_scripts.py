import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], cwd=ROOT, text=True, capture_output=True, check=False)


def test_testbed_import_dry_run_reports_bundle_without_writing_database(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "network").mkdir(parents=True)
    (bundle / "linux").mkdir()
    (bundle / "manifest.yaml").write_text(
        """
scenario_id: cloud-testbed-chain-001
run_id: run_cloud_testbed_001
timezone: UTC+08:00
nodes:
  - node_id: N4
    role: web_server
    hostname: web01
    sensors: ["auditd", "zeek"]
""".strip(),
        encoding="utf-8",
    )
    (bundle / "network" / "conn.log").write_text(
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\n1710000000.1\tC1\t10.0.0.5\t10.0.0.8\n",
        encoding="utf-8",
    )
    (bundle / "network" / "zeek_dns.jsonl").write_text(
        '{"ts":1710000000.2,"uid":"D1","id.orig_h":"10.0.0.5","query":"c2.example"}\n',
        encoding="utf-8",
    )
    (bundle / "linux" / "web_audit.log").write_text(
        'type=SYSCALL msg=audit(1710000001.1:42): arch=c000003e syscall=59 success=yes exe="/bin/bash"\n',
        encoding="utf-8",
    )

    result = run_script("scripts/testbed_import_dry_run.py", "--bundle", str(bundle))

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["writes_database"] is False
    assert payload["detection_generated"] is False
    assert payload["run_id"] == "run_cloud_testbed_001"
    assert payload["source_counts"]["zeek"] == 2
    assert payload["source_counts"]["auditd"] == 1
    assert payload["missing_critical_data"] == []


def test_demo_readiness_empty_database_reports_preparation_command(tmp_path):
    env = {
        "TRACEGUARD_DATA_DIR": str(tmp_path),
        "TRACEGUARD_DATABASE_PATH": str(tmp_path / "missing.db"),
        "TRACEGUARD_RAW_ARCHIVE_DIR": str(tmp_path / "raw"),
        "TRACEGUARD_REPORT_DIR": str(tmp_path / "reports"),
        "TRACEGUARD_NEO4J_ENABLED": "false",
        **dict(),
    }
    import os

    merged_env = os.environ.copy()
    merged_env.update(env)
    result = subprocess.run(
        [sys.executable, "scripts/demo_readiness.py"],
        cwd=ROOT,
        env=merged_env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    sqlite_check = next(item for item in payload["checks"] if item["name"] == "sqlite_demo_data")
    assert sqlite_check["ok"] is False
    assert "replay_scenario.py" in sqlite_check["detail"]["prepare_demo_command"]
