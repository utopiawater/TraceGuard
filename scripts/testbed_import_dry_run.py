import argparse
import json
import re
import sys
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analysis.service import AnalysisTaskService
from app.analysis.manifest import environment_policy, read_manifest_file
from app.collectors import envelope_from_payload
from app.contracts import SourceDescriptor
from app.contracts.common import SourceKind
from app.core.time import parse_timestamp
from app.normalizers import ApplicationWebAdapter, AuditdAdapter, DarpaTcE3CadetsAdapter, NormalizerRegistry, SampleAttackDatasetAdapter, SysmonAdapter, WindowsSecurityAdapter, WazuhAdapter, ZeekAdapter
from app.normalizers.auditd import AUDIT_RE
from app.normalizers.base import AdapterError


SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".xml", ".log", ".pcap", ".evtx"}


def read_manifest(path: Path) -> dict[str, Any]:
    return read_manifest_file(path)


def classify(path: Path, service: AnalysisTaskService | None = None) -> str:
    if service is not None:
        recognized = service._recognize(path)
        if recognized.source_kind:
            return recognized.source_kind.value
        if recognized.evaluation_only:
            return "ground_truth"
        if recognized.parser_status == "missing_parser":
            return "%s_missing_parser" % recognized.kind.lower().replace(" ", "_")
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


def build_registry() -> NormalizerRegistry:
    return NormalizerRegistry([
        SysmonAdapter(), WindowsSecurityAdapter(), ZeekAdapter(), WazuhAdapter(), AuditdAdapter(),
        DarpaTcE3CadetsAdapter(), SampleAttackDatasetAdapter(), ApplicationWebAdapter(),
    ])


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


def count_via_analysis_service(path: Path, service: AnalysisTaskService, registry: NormalizerRegistry, policy: dict[str, Any] | None = None) -> tuple[int, int, int, list[str]]:
    recognized = service._recognize(path)
    if recognized.parser_status == "missing_parser":
        return 0, 0, 0, ["missing parser for %s" % recognized.kind]
    if recognized.evaluation_only or not recognized.source_kind:
        fallback_parseable, fallback_failed = count_records(path, classify(path))
        return fallback_parseable, fallback_failed, 0, []
    try:
        payloads = list(service._payloads(path, recognized.payload_format, recognized.dataset))
    except Exception as exc:
        return 0, 1, 0, [str(exc)]

    normalized = 0
    failed = 0
    errors: list[str] = []
    for index, payload in enumerate(payloads):
        if isinstance(payload, dict):
            payload = dict(payload)
            dataset = payload.pop("_dataset", recognized.dataset)
        else:
            dataset = recognized.dataset
        kind = service._windows_kind_from_xml(payload, recognized.source_kind)
        event_time_raw = service._event_time(payload)
        try:
            policy = policy or {}
            observed = parse_timestamp(event_time_raw, policy.get("default_timezone")) if event_time_raw is not None else parse_timestamp(0)
            aliases = policy.get("asset_aliases")
            path_hint = service._host_hint_from_path(path, aliases if isinstance(aliases, dict) else None)
            host_hint = service._host_hint(payload)
            if host_hint and host_hint.lower() in {"localhost", "."}:
                host_hint = path_hint or host_hint
            source = SourceDescriptor(
                kind=kind,
                product="dry-run",
                dataset=dataset,
                sensor_id=service._sensor_id(path, payload, kind),
                host_hint=host_hint or path_hint,
                source_record_id="%s:%d" % (path.name, index),
            )
            payload_format = "json" if recognized.payload_format == "pcap_ref" else "xml" if recognized.payload_format == "evtx" else recognized.payload_format
            raw = envelope_from_payload(source, payload, payload_format, event_time_raw, "dry-run://%s#%d" % (path, index), observed, {"dry_run": True, **policy})
            normalized += len(registry.normalize(raw))
        except (AdapterError, ValueError, TypeError) as exc:
            failed += 1
            if len(errors) < 5:
                errors.append(str(exc))
    parseable = max(len(payloads), normalized) if recognized.payload_format in {"text", "xml"} else len(payloads)
    return parseable, failed, normalized, errors


def extract_times(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    candidates = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", text)
    candidates += re.findall(r"\b1[5-9]\d{8}\.\d+\b", text)
    candidates += re.findall(r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}", text)
    candidates += re.findall(r"\d{2}/[A-Z][a-z]{2}/\d{4} \d{2}:\d{2}:\d{2}", text)
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

    input_bundle = args.bundle.resolve()
    temp_context = None
    service = object.__new__(AnalysisTaskService)
    if input_bundle.is_file():
        temp_root = ROOT / "data" / "testbed_dry_run_tmp"
        temp_root.mkdir(parents=True, exist_ok=True)
        temp_context = temp_root / ("traceguard_dry_run_%d" % int(time.time() * 1000))
        bundle = temp_context / "expanded"
        bundle.mkdir(parents=True, exist_ok=True)
        task = {"identification": {"warnings": []}}
        service._expand_input(input_bundle, bundle, task)
        archive_warnings = task["identification"]["warnings"]
    else:
        bundle = input_bundle
        archive_warnings = []
    manifest_path = bundle / args.manifest
    if not manifest_path.exists():
        manifest_path = next((bundle / name for name in ("traceguard_manifest.json", "manifest.json", "traceguard_manifest.yaml", "traceguard_manifest.yml", "manifest.yml") if (bundle / name).exists()), manifest_path)
    manifest = read_manifest(manifest_path)
    policy = environment_policy(manifest)
    manifest_names = {"traceguard_manifest.json", "manifest.json", "traceguard_manifest.yaml", "traceguard_manifest.yml", "manifest.yaml", "manifest.yml"}
    files = [path for path in bundle.rglob("*") if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES and path.name not in manifest_names]
    registry = build_registry()
    source_counts: Counter[str] = Counter()
    file_reports = []
    all_times = []

    for path in files:
        recognized = service._recognize(path)
        source_kind = classify(path, service)
        parseable, failed, normalized, errors = count_via_analysis_service(path, service, registry, policy)
        source_counts[source_kind] += parseable
        times = extract_times(path)
        all_times.extend(times)
        file_reports.append({
            "path": str(path.relative_to(bundle)),
            "source_kind": source_kind,
            "dataset": recognized.dataset,
            "parseable_records": parseable,
            "normalized_events": normalized,
            "unparseable_records": failed,
            "parse_errors": errors,
            "time_min": min(times) if times else None,
            "time_max": max(times) if times else None,
        })

    nodes = manifest.get("nodes") if isinstance(manifest.get("nodes"), list) else []
    source_kinds = sorted({item["source_kind"] for item in file_reports if item["source_kind"] != "unsupported"})
    missing = []
    if manifest.get("missing"):
        missing.append("manifest.yaml missing")
    if not nodes:
        missing.append("manifest.nodes missing or empty")
    if not any(kind in source_kinds for kind in {"zeek", "zeek.conn", "zeek.http", "pcap_missing_parser"}):
        missing.append("network zeek/pcap logs missing")
    if not any(kind in source_kinds for kind in {"sysmon", "windows_security", "auditd", "wazuh", "windows.evtx"}):
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
        "bundle": str(input_bundle),
        "scenario_id": manifest.get("scenario_id"),
        "run_id": manifest.get("run_id"),
        "timezone": manifest.get("default_timezone") or manifest.get("timezone"),
        "policy": policy,
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
        "normalized_events": sum(item["normalized_events"] for item in file_reports),
        "unparseable_records": sum(item["unparseable_records"] for item in file_reports),
        "missing_critical_data": missing,
        "archive_warnings": archive_warnings,
        "writes_database": False,
        "detection_generated": False,
        "note": "Dry-run 只检查文件、时间和可解析性；Ground Truth/attack_timeline 不会生成 Detection 或 AttackChain。",
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if temp_context is not None:
        shutil.rmtree(temp_context, ignore_errors=True)
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
