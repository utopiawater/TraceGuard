import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.contracts import RawEventEnvelope, SourceDescriptor
from app.contracts.common import SourceKind
from app.core.ids import sha256_text, stable_id
from app.core.time import parse_timestamp, utc_now


DATASET_ID = "darpa_tc_e3_cadets"
DATASET_NAME = "DARPA TC E3 CADets"
SCENARIO_ID = "E3-CADETS-20180412-nginx"
EVENT_FILES = ("process_events.json", "network_events.json", "file_events.json")
GROUND_TRUTH_EXPLANATION = (
    "该 DARPA TC E3 CADets 实验切片仅提供 IOC 命中及相关上下文信息，不具备完备逐事件 "
    "benign/attack 二分类真值，因此不报告二分类 Precision、Recall 和 F1。"
)
EVALUATION_ONLY_FIELDS = {"attack_label", "selection_reason"}


def _processed_dir(dataset_root: Path) -> Path:
    return Path(dataset_root) / "processed_dataset"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_dataset_records(dataset_root: Path) -> Iterable[tuple[str, int, Dict[str, Any]]]:
    for name in EVENT_FILES:
        path = _processed_dir(dataset_root) / name
        records = _load_json(path)
        for index, record in enumerate(records):
            yield name, index, record


def inspect_dataset(dataset_root: Path) -> Dict[str, Any]:
    dataset_root = Path(dataset_root)
    counts: Dict[str, int] = {}
    event_types: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    processes: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    timestamps = []
    event_ids = []
    source_shapes: Counter[str] = Counter()
    destination_shapes: Counter[str] = Counter()
    file_shapes: Counter[str] = Counter()
    subject_shapes: Counter[str] = Counter()

    for name in EVENT_FILES:
        path = _processed_dir(dataset_root) / name
        records = _load_json(path)
        counts[name] = len(records)
        for record in records:
            event_types[str(record.get("event_type"))] += 1
            actions[str(record.get("action"))] += 1
            hosts[str(record.get("host"))] += 1
            processes[str(record.get("process"))] += 1
            labels[str(record.get("attack_label"))] += 1
            timestamps.append(record.get("timestamp"))
            event_ids.append(record.get("event_id"))
            source_shapes[str(sorted((record.get("source") or {}).keys()))] += 1
            destination_shapes[str(sorted((record.get("destination") or {}).keys()))] += 1
            file_shapes[str(bool(record.get("object_path")))] += 1
            subject_shapes[str(sorted(k for k in ("subject_id", "parent_subject_id", "object_id", "object2_id") if record.get(k)))] += 1

    manifest_path = dataset_root / "source_metadata" / "selection_manifest.json"
    manifest = _load_json(manifest_path) if manifest_path.exists() else {}
    scenario = manifest.get("scenario", {})
    total = sum(counts.values())
    return {
        "dataset_id": DATASET_ID,
        "dataset_name": DATASET_NAME,
        "source": "DARPA Transparent Computing E3 / ta1-cadets-e3-official-2",
        "scenario": scenario.get("id", SCENARIO_ID),
        "scenario_description": scenario.get("source", "CADets Nginx/Drakon/Micro APT scenario"),
        "counts": counts,
        "total_events": total,
        "event_type_distribution": dict(event_types.most_common()),
        "action_distribution": dict(actions.most_common()),
        "host_distribution": dict(hosts.most_common()),
        "process_distribution": dict(processes.most_common(50)),
        "attack_label_distribution": dict(labels.most_common()),
        "network_field_shapes": {"source": dict(source_shapes), "destination": dict(destination_shapes)},
        "file_field_shapes": dict(file_shapes),
        "subject_object_shapes": dict(subject_shapes),
        "timestamp_format": "UTC ISO8601 with nanosecond fractional seconds and Z suffix",
        "timestamp_min": min(timestamps) if timestamps else None,
        "timestamp_max": max(timestamps) if timestamps else None,
        "event_id_format": "cadets:record:<original-record-number>",
        "unique_event_ids": len(set(event_ids)),
    }


def _sanitized_payload(record: Dict[str, Any], dataset_file: str, index: int) -> Dict[str, Any]:
    payload = {key: value for key, value in record.items() if key not in EVALUATION_ONLY_FIELDS}
    payload["dataset_file"] = dataset_file
    payload["dataset_index"] = index
    return payload


def load_raw_envelopes(dataset_root: Path) -> List[RawEventEnvelope]:
    dataset_root = Path(dataset_root)
    ingested = utc_now()
    envelopes: List[RawEventEnvelope] = []
    for dataset_file, index, record in iter_dataset_records(dataset_root):
        payload = _sanitized_payload(record, dataset_file, index)
        timestamp = parse_timestamp(record["timestamp"])
        event_id = str(record["event_id"])
        raw_id = stable_id("raw", DATASET_ID, dataset_file, event_id)
        host = str(record.get("host") or "cadets")
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        envelopes.append(RawEventEnvelope(
            raw_id=raw_id,
            source=SourceDescriptor(
                kind=SourceKind.dataset,
                product=DATASET_NAME,
                dataset=DATASET_ID,
                sensor_id="cadets:%s" % host.lower(),
                host_hint=host,
                source_record_id=event_id,
            ),
            source_record_id=event_id,
            event_time_raw=record.get("timestamp"),
            observed_time=timestamp,
            ingested_time=ingested,
            payload_format="json",
            payload=payload,
            raw_ref="%s#%s" % ((_processed_dir(dataset_root) / dataset_file).as_posix(), event_id),
            raw_sha256=sha256_text(serialized),
            labels={"dataset_id": DATASET_ID, "dataset_file": dataset_file},
        ))
    return envelopes


def load_evaluation_ground_truth(dataset_root: Path) -> Dict[str, Any]:
    manifest_path = Path(dataset_root) / "source_metadata" / "selection_manifest.json"
    manifest = _load_json(manifest_path) if manifest_path.exists() else {}
    labels: Dict[str, str] = {}
    reasons: Dict[str, List[str]] = {}
    for _, _, record in iter_dataset_records(dataset_root):
        event_id = str(record.get("event_id"))
        labels[event_id] = str(record.get("attack_label"))
        reasons[event_id] = list(record.get("selection_reason") or [])
    return {
        "manifest": manifest,
        "labels": labels,
        "selection_reasons": reasons,
        "ioc_event_ids": sorted(event_id for event_id, label in labels.items() if label == "ioc_match"),
        "context_event_ids": sorted(event_id for event_id, label in labels.items() if label == "context"),
    }


def build_dataset_run_report(
    dataset_root: Path,
    run_id: str,
    pipeline_result,
    repository,
    runtime_seconds: float,
    investigation_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    inspection = inspect_dataset(dataset_root)
    truth = load_evaluation_ground_truth(dataset_root)
    input_records = inspection["total_events"]
    normalized = len(pipeline_result.events)
    warnings = [warning for event in pipeline_result.events for warning in event.provenance.mapping_warnings]
    unknown_action_count = sum(1 for warning in warnings if "unknown darpa action" in warning)
    detected_original_event_ids = {
        event.extensions.get("dataset", {}).get("original_event_id")
        for event in pipeline_result.events
        if any(event.event_id in detection.event_ids for detection in pipeline_result.detections)
    }
    detected_original_event_ids.discard(None)
    ioc_event_ids = set(truth["ioc_event_ids"])
    ioc_covered = len(ioc_event_ids & detected_original_event_ids)
    ioc_coverage_analysis = _analyze_uncovered_ioc(dataset_root, ioc_event_ids - detected_original_event_ids)
    chain_stages = sorted({step.stage for chain in pipeline_result.chains for step in chain.steps})
    expected_stages = ["execution", "privilege_escalation", "collection", "command_and_control"]
    covered_stages = [stage for stage in expected_stages if stage in chain_stages]
    evidence_ids = {item.evidence_id for item in pipeline_result.evidence}
    important_refs = [*pipeline_result.detections, *[step for chain in pipeline_result.chains for step in chain.steps]]
    evidence_backtrace_hits = sum(1 for item in important_refs if getattr(item, "evidence_ids", None) and all(eid in evidence_ids for eid in item.evidence_ids))
    detection_rule_counts = Counter(item.rule_id for item in pipeline_result.detections)
    technique_ids = sorted({mapping.subtechnique_id or mapping.technique_id for detection in pipeline_result.detections for mapping in detection.attack_mappings})
    eps = round(normalized / runtime_seconds, 3) if runtime_seconds > 0 else None
    return {
        "dataset_id": DATASET_ID,
        "dataset_name": DATASET_NAME,
        "source": inspection["source"],
        "scenario": inspection["scenario"],
        "scenario_description": inspection["scenario_description"],
        "run_id": run_id,
        "status": "completed" if normalized else "no_new_records",
        "input_records": input_records,
        "records": input_records,
        "accepted_raw": pipeline_result.accepted_raw,
        "normalized_records": normalized,
        "normalized": normalized,
        "failed_records": max(pipeline_result.accepted_raw - normalized, 0),
        "duplicate_records": max(input_records - pipeline_result.accepted_raw, 0) if not normalized else 0,
        "mapping_rate": round(normalized / input_records, 6) if input_records else 0,
        "unknown_action_count": unknown_action_count,
        "mapping_warnings": dict(Counter(warnings).most_common(50)),
        "action_mapping_distribution": dict(Counter(event.action for event in pipeline_result.events).most_common()),
        "input_action_distribution": inspection["action_distribution"],
        "entity_count": len(pipeline_result.graph_entities),
        "session_count": len(pipeline_result.sessions),
        "detection_count": len(pipeline_result.detections),
        "detection_rule_counts": dict(detection_rule_counts.most_common()),
        "evidence_count": len(pipeline_result.evidence),
        "attack_technique_ids": technique_ids,
        "technique_ids": technique_ids,
        "attack_technique_count": len(technique_ids),
        "technique_count": len(technique_ids),
        "attack_chain_count": len(pipeline_result.chains),
        "chain_count": len(pipeline_result.chains),
        "attack_chains": [
            {
                "chain_id": chain.chain_id,
                "score": chain.score,
                "completeness": chain.completeness,
                "steps": [
                    {
                        "stage": step.stage,
                        "technique_id": step.technique_id,
                        "detection_ids": step.detection_ids,
                        "event_ids": step.event_ids,
                        "evidence_ids": step.evidence_ids,
                    }
                    for step in chain.steps
                ],
                "evidence_ids": chain.evidence_ids,
            }
            for chain in pipeline_result.chains
        ],
        "ioc_coverage": {"covered": ioc_covered, "total": len(ioc_event_ids), "rate": round(ioc_covered / len(ioc_event_ids), 6) if ioc_event_ids else None},
        "ioc_coverage_analysis": ioc_coverage_analysis,
        "stage_coverage": {"covered": len(covered_stages), "total": len(expected_stages), "rate": round(len(covered_stages) / len(expected_stages), 6), "stages": covered_stages},
        "evidence_backtrace_rate": round(evidence_backtrace_hits / len(important_refs), 6) if important_refs else 1.0,
        "chain_evidence_coverage": [
            {"chain_id": chain.chain_id, "covered": sum(1 for step in chain.steps if step.evidence_ids), "total": len(chain.steps)}
            for chain in pipeline_result.chains
        ],
        "runtime_seconds": round(runtime_seconds, 3),
        "events_per_second": eps,
        "precision": None,
        "recall": None,
        "f1": None,
        "f1_reason": GROUND_TRUTH_EXPLANATION,
        "limitations": [GROUND_TRUTH_EXPLANATION, "attack_graph.json、attack_timeline.json 与 agent_input.json 未用于生成 Detection 或 AttackChain。"],
        "inspection": inspection,
        "multi_agent": investigation_summary,
    }


def _analyze_uncovered_ioc(dataset_root: Path, uncovered_event_ids: set[str]) -> Dict[str, Any]:
    records = [record for _, _, record in iter_dataset_records(dataset_root) if str(record.get("event_id")) in uncovered_event_ids]
    low_semantic_actions = {"aue_recvfrom", "aue_sendto", "aue_close", "aue_read", "aue_fcntl", "aue_lseek"}
    low_semantic_count = sum(1 for record in records if str(record.get("action")) in low_semantic_actions)
    network_count = sum(1 for record in records if record.get("source") or record.get("destination"))
    file_count = sum(1 for record in records if record.get("object_path"))
    action_counts = Counter(str(record.get("action")) for record in records)
    event_type_counts = Counter(str(record.get("event_type")) for record in records)
    process_counts = Counter(str(record.get("process")) for record in records)
    file_paths = Counter(str(record.get("object_path")) for record in records if record.get("object_path"))
    reasons = Counter(",".join(record.get("selection_reason") or []) for record in records)
    gaps = []
    if any(str(record.get("event_type")) in {"open", "modify_file_attributes", "unlink", "execute"} and str(record.get("object_path") or "").startswith(("/tmp/", "/var/log/")) for record in records):
        gaps.append("可考虑后续增加通用文件落地/授权变更/删除序列检测，但本次未为提高 IOC coverage 自动新增规则。")
    return {
        "uncovered_ioc_events": len(records),
        "action_distribution": dict(action_counts.most_common(20)),
        "event_type_distribution": dict(event_type_counts.most_common(20)),
        "process_distribution": dict(process_counts.most_common(20)),
        "selection_reason_distribution": dict(reasons.most_common(20)),
        "network_ioc_events": network_count,
        "file_ioc_events": file_count,
        "top_file_paths": dict(file_paths.most_common(20)),
        "low_semantic_syscall_events": low_semantic_count,
        "low_semantic_rate": round(low_semantic_count / len(records), 6) if records else None,
        "assessment": "未覆盖 IOC 主要由重复网络收发系统调用构成；少量文件 IOC 属于落地、chmod、unlink、执行序列，应作为后续通用规则候选而不是本次用 Ground Truth 追指标。",
        "potential_detection_gaps": gaps,
    }


def write_dataset_run_report(report: Dict[str, Any], data_dir: Path) -> Path:
    target = Path(data_dir) / "dataset_run_report.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def discover_dataset_reports(settings_data_dir: Path, project_root: Path) -> List[Dict[str, Any]]:
    candidates = [
        Path(settings_data_dir) / "dataset_run_report.json",
        project_root / "data" / "dataset_e3" / "dataset_run_report.json",
    ]
    candidates.extend((project_root / "data").glob("*/dataset_run_report.json") if (project_root / "data").exists() else [])
    reports = []
    seen = set()
    for path in candidates:
        path = path.resolve()
        if path in seen or not path.exists():
            continue
        seen.add(path)
        try:
            payload = _load_json(path)
            payload["report_path"] = str(path)
            payload["report_mtime"] = path.stat().st_mtime
            reports.append(payload)
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(reports, key=lambda item: (item.get("report_mtime") or 0, item.get("run_id") or ""), reverse=True)
