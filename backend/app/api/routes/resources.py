from pathlib import Path

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import graph, repository
from app.api.envelope import response
from app.datasets.darpa_tc_e3 import discover_dataset_reports
from app.knowledge import MappingFileProvider
from app.repositories import SQLiteRepository

router = APIRouter(tags=["resources"])


def unavailable(resource: str, dependency: str) -> dict:
    return response([], ["%s 尚无可展示记录；%s 尚未接入。" % (resource, dependency)])


@router.get("/entities")
def entities(projector=Depends(graph)) -> dict:
    return response([item.model_dump(mode="json") for item in projector.entities.values()])


@router.get("/hosts")
def hosts(repo: SQLiteRepository = Depends(repository)) -> dict:
    seen = {}
    for event in repo.query_events(limit=50000):
        if event.host:
            item = seen.setdefault(event.host.entity_id, {"host_id": event.host.entity_id, "hostname": event.host.display_name, "last_seen": event.event_time.isoformat(), "logins": 0, "process": 0, "file": 0, "registry": 0, "privilege": 0, "memory": 0})
            item["last_seen"] = max(item["last_seen"], event.event_time.isoformat())
            item["last_action"] = event.action
            if event.action.startswith("auth."): item["logins"] += 1
            if event.action.startswith("process."): item["process"] += 1
            if event.action.startswith("file."): item["file"] += 1
            if event.action.startswith("registry."): item["registry"] += 1
            if "privilege" in event.action: item["privilege"] += 1
            if event.action.startswith("memory."): item["memory"] += 1
    return response(list(seen.values()))


@router.get("/network")
def network(repo: SQLiteRepository = Depends(repository)) -> dict:
    values = [{
        "event_id": item.event_id, "event_time": item.event_time.isoformat(), "source": item.source.kind.value,
        "action": item.action, "transport": item.network.transport, "application": item.network.application,
        "src": "%s:%s" % (item.network.src.ip or item.network.src.host_id or "?", item.network.src.port if item.network.src.port is not None else "?"),
        "dst": "%s:%s" % (item.network.dst.ip or item.network.dst.host_id or "?", item.network.dst.port if item.network.dst.port is not None else "?"),
        "bytes_sent": item.network.bytes_sent, "session_id": item.network.session_id, "message": item.message,
    } for item in repo.query_events(limit=50000) if item.network]
    return response(values)


@router.get("/attack")
def attack(repo: SQLiteRepository = Depends(repository)) -> dict:
    coverage = {}
    attack_knowledge = MappingFileProvider(Path(__file__).parents[4] / "knowledge" / "attack" / "mappings.json")
    for detection in repo.list_detections(50000):
        for mapping in detection.attack_mappings:
            key = mapping.subtechnique_id or mapping.technique_id
            technique = attack_knowledge.technique(key)
            item = coverage.setdefault(key, {"technique_id": key, "technique_name": technique.get("name", "Unknown"), "detection_count": 0, "evidence_count": 0, "attack_version": mapping.attack_version})
            item["detection_count"] += 1
            item["evidence_count"] += len(detection.evidence_ids)
    return response(list(coverage.values()))


@router.get("/datasets")
def datasets(request: Request) -> dict:
    project_root = Path(__file__).parents[4]
    reports = discover_dataset_reports(request.app.state.settings.data_dir, project_root)
    if not reports:
        return unavailable("数据集实验", "公开数据集运行报告")
    rows = []
    for report in reports:
        rows.append({
            "dataset_id": report.get("dataset_id"),
            "dataset_name": report.get("dataset_name"),
            "source": report.get("source"),
            "scenario": report.get("scenario"),
            "run_id": report.get("run_id"),
            "status": report.get("status"),
            "records": report.get("records") or report.get("input_records"),
            "normalized_records": report.get("normalized_records") or report.get("normalized"),
            "failed_records": report.get("failed_records"),
            "mapping_rate": report.get("mapping_rate"),
            "detection_count": report.get("detection_count"),
            "technique_ids": report.get("technique_ids") or report.get("attack_technique_ids"),
            "technique_count": report.get("technique_count") or report.get("attack_technique_count"),
            "chain_count": report.get("chain_count") or report.get("attack_chain_count"),
            "ioc_coverage": report.get("ioc_coverage"),
            "ioc_coverage_analysis": report.get("ioc_coverage_analysis"),
            "stage_coverage": report.get("stage_coverage"),
            "evidence_backtrace_rate": report.get("evidence_backtrace_rate"),
            "runtime_seconds": report.get("runtime_seconds"),
            "precision": report.get("precision"),
            "recall": report.get("recall"),
            "f1": report.get("f1"),
            "f1_reason": report.get("f1_reason"),
            "limitations": report.get("limitations", []),
            "report_path": report.get("report_path"),
        })
    return response(rows)


@router.get("/sources")
def sources(repo: SQLiteRepository = Depends(repository)) -> dict:
    events = repo.query_events(limit=50000)
    values = {}
    for event in events:
        values[event.source.sensor_id] = {"sensor_id": event.source.sensor_id, "kind": event.source.kind.value, "dataset": event.source.dataset, "last_event_time": event.event_time.isoformat(), "status": "healthy"}
    return response(list(values.values()))
