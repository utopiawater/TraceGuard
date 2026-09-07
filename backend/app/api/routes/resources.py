from fastapi import APIRouter, Depends

from app.api.dependencies import graph, repository
from app.api.envelope import response
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
    for event in repo.list_events(500):
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
    } for item in repo.list_events(500) if item.network]
    return response(values)


@router.get("/attack")
def attack(repo: SQLiteRepository = Depends(repository)) -> dict:
    coverage = {}
    for detection in repo.list_detections(500):
        for mapping in detection.attack_mappings:
            key = mapping.subtechnique_id or mapping.technique_id
            item = coverage.setdefault(key, {"technique_id": key, "detection_count": 0, "evidence_count": 0, "attack_version": mapping.attack_version})
            item["detection_count"] += 1
            item["evidence_count"] += len(detection.evidence_ids)
    return response(list(coverage.values()))


@router.get("/datasets")
def datasets() -> dict:
    return unavailable("数据集实验", "公开数据集 Adapter")


@router.get("/sources")
def sources(repo: SQLiteRepository = Depends(repository)) -> dict:
    events = repo.list_events(500)
    values = {}
    for event in events:
        values[event.source.sensor_id] = {"sensor_id": event.source.sensor_id, "kind": event.source.kind.value, "dataset": event.source.dataset, "last_event_time": event.event_time.isoformat(), "status": "healthy"}
    return response(list(values.values()))
