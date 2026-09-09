import argparse
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.time import parse_timestamp
from app.normalizers.auditd import AUDIT_RE


SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".xml", ".log"}


def scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        try:
            return ast.literal_eval(value)
        except Exception:
            return value
    return value.strip("'\"")


def read_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"missing": True, "nodes": []}
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    data: dict[str, Any] = {"nodes": []}
    section = None
    current_node: dict[str, Any] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith(" "):
            key, _, value = raw_line.partition(":")
            section = key.strip()
            if value.strip():
                data[section] = scalar(value)
            elif section == "nodes":
                data.setdefault("nodes", [])
            continue
        stripped = raw_line.strip()
        if section == "nodes" and stripped.startswith("- "):
            current_node = {}
            data.setdefault("nodes", []).append(current_node)
            stripped = stripped[2:].strip()
            if stripped:
                key, _, value = stripped.partition(":")
                current_node[key.strip()] = scalar(value)
        elif section == "nodes" and current_node is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current_node[key.strip()] = scalar(value)
    return data


def classify(path: Path) -> str:
    name = path.name.lower()
    parent = path.parent.name.lower()
    if "zeek" in parent or name.startswith(("zeek_", "conn.", "dns.", "http.", "files.", "weird.", "notice.", "icmp.")):
        return "zeek"
    if "audit" in name:
        return "auditd"
    if "wazuh" in name:
        return "wazuh"
    if "sysmon" in name:
        return "sysmon"
    if "security" in name or "windows" in parent:
        return "windows_security"
    return "unsupported"


def parse_json_records(text: str) -> tuple[int, int]:
    try:
        loaded = json.loads(text)
        rows = loaded.get("records", loaded) if isinstance(loaded, dict) else loaded
        if isinstance(rows, list):
            return len(rows), 0
        return 1, 0
    except Exception:
        parseable = 0
        failed = 0
        for line in [line for line in text.splitlines() if line.strip()]:
            try:
                json.loads(line)
                parseable += 1
            except Exception:
                failed += 1
        return parseable, failed


def count_records(path: Path, source_kind: str) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        return parse_json_records(text)
    if path.suffix.lower() == ".xml":
        count = len(re.findall(r"<Event\b", text))
        return (count or 1), 0
    if source_kind == "auditd":
        groups = {"%s:%s" % (match.group("timestamp"), match.group("serial")) for match in AUDIT_RE.finditer(text)}
        return len(groups), 0
    if source_kind == "zeek":
        rows = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
        return len(rows), 0
    rows = [line for line in text.splitlines() if line.strip()]
    return 0, len(rows)


def extract_times(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    candidates = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", text)
    candidates += re.findall(r"\b1[5-9]\d{8}\.\d+\b", text)
    values = []
    for item in candidates[:500]:
        try:
            values.append(parse_timestamp(float(item)).isoformat() if re.fullmatch(r"\d+\.\d+", item) else parse_timestamp(item).isoformat())
        except Exception:
            continue
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run a TraceGuard cloud testbed bundle without writing the database.")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest", default="manifest.yaml")
    args = parser.parse_args()

    bundle = args.bundle.resolve()
    manifest_path = bundle / args.manifest
    manifest = read_manifest(manifest_path)
    files = [path for path in bundle.rglob("*") if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES and path.name != Path(args.manifest).name]
    source_counts: Counter[str] = Counter()
    file_reports = []
    all_times = []

    for path in files:
        source_kind = classify(path)
        parseable, failed = count_records(path, source_kind)
        source_counts[source_kind] += parseable
        times = extract_times(path)
        all_times.extend(times)
        file_reports.append({
            "path": str(path.relative_to(bundle)),
            "source_kind": source_kind,
            "parseable_records": parseable,
            "unparseable_records": failed,
            "time_min": min(times) if times else None,
            "time_max": max(times) if times else None,
        })

    nodes = manifest.get("nodes") if isinstance(manifest.get("nodes"), list) else []
    source_kinds = sorted(kind for kind, count in source_counts.items() if count > 0)
    missing = []
    if manifest.get("missing"):
        missing.append("manifest.yaml missing")
    if not nodes:
        missing.append("manifest.nodes missing or empty")
    if not any(kind in source_kinds for kind in {"zeek"}):
        missing.append("network zeek logs missing")
    if not any(kind in source_kinds for kind in {"sysmon", "windows_security", "auditd", "wazuh"}):
        missing.append("host telemetry logs missing")

    clock_offsets = []
    for path in files:
        if "health" not in path.name.lower():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        values = payload if isinstance(payload, list) else [payload]
        for item in values:
            if isinstance(item, dict):
                for key in ("clock_offset_ms", "time_offset_ms", "ntp_offset_ms"):
                    if isinstance(item.get(key), (int, float)):
                        clock_offsets.append(float(item[key]))

    output = {
        "status": "dry_run_complete",
        "bundle": str(bundle),
        "scenario_id": manifest.get("scenario_id"),
        "run_id": manifest.get("run_id"),
        "timezone": manifest.get("timezone"),
        "nodes": nodes,
        "node_count": len(nodes),
        "files": file_reports,
        "file_count": len(file_reports),
        "source_counts": dict(source_counts),
        "source_kinds": source_kinds,
        "time_range": {"start": min(all_times) if all_times else None, "end": max(all_times) if all_times else None},
        "time_offset_ms": {
            "observed": clock_offsets,
            "max_abs": max((abs(item) for item in clock_offsets), default=None),
            "status": "observed" if clock_offsets else "unknown",
            "note": "缺少 capture_health/time_sync 结构化 offset 时，dry-run 不声称时间已同步。",
        },
        "parseable_records": sum(item["parseable_records"] for item in file_reports),
        "unparseable_records": sum(item["unparseable_records"] for item in file_reports),
        "missing_critical_data": missing,
        "writes_database": False,
        "detection_generated": False,
        "note": "Dry-run 只检查文件、时间和可解析性；Ground Truth/attack_timeline 不会生成 Detection 或 AttackChain。",
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
