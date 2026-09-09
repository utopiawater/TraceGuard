from uuid import uuid4
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from app.api.dependencies import graph, investigation_service, repository
from app.agents.service import InvestigationService
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["investigation"])


@router.get("/detections")
def detections(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    return response([item.model_dump(mode="json") for item in repo.list_detections(limit, run_id=run_id, offset=offset)], total=repo.count_table("detections", run_id=run_id))


@router.get("/detections/{detection_id}")
def detection_detail(detection_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    item = repo.get_detection(detection_id)
    if not item:
        raise HTTPException(status_code=404, detail="detection not found")
    return response(item.model_dump(mode="json"))


@router.get("/alerts")
def alerts(repo: SQLiteRepository = Depends(repository)) -> dict:
    values = [{"alert_id": item.detection_id, "detection_id": item.detection_id, "title": item.title, "severity": item.severity, "status": item.status, "evidence_count": len(item.evidence_ids)} for item in repo.list_detections(500)]
    return response(values)


@router.get("/chains")
def chains(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    return response([item.model_dump(mode="json") for item in repo.list_chains(limit, run_id=run_id, offset=offset)], total=repo.count_table("attack_chains", run_id=run_id))


@router.get("/chains/{chain_id}")
def chain(chain_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    item = repo.get_chain(chain_id)
    if not item:
        raise HTTPException(status_code=404, detail="attack chain not found")
    return response(item.model_dump(mode="json"))


@router.get("/chains/{chain_id}/graph")
def chain_graph(chain_id: str, repo: SQLiteRepository = Depends(repository), projector=Depends(graph)) -> dict:
    item = repo.get_chain(chain_id)
    if not item:
        raise HTTPException(status_code=404, detail="attack chain not found")
    allowed_ids = set(item.entity_ids) | set(item.detection_ids) | set(item.technique_ids) | {sid for step in item.steps for sid in step.session_ids}
    for evidence_id in item.evidence_ids:
        evidence = repo.get_evidence(evidence_id)
        if evidence and repo.get_evidence_run_id(evidence_id) == item.run_id:
            allowed_ids.update(evidence.entity_ids)
    nodes = [value for value in projector.entities.values() if value.entity_id in allowed_ids]
    node_ids = {node.entity_id for node in nodes}
    edges = [value for value in projector.relations.values() if value.source_entity_id in node_ids and value.target_entity_id in node_ids]
    return response({
        "nodes": [value.model_dump(mode="json") for value in nodes],
        "edges": [value.model_dump(mode="json") for value in edges],
        "limit": None,
        "chain_id": chain_id,
        "run_id": item.run_id,
        "runtime": projector.status() if hasattr(projector, "status") else {"configured": False, "connected": False, "backend": "memory"},
    })


@router.post("/chains/{chain_id}/investigate")
def investigate_chain(
    chain_id: str,
    background: BackgroundTasks,
    scope: Literal["full", "quick"] = Query(default="full"),
    max_steps: int = Query(default=12, ge=4, le=12),
    repo: SQLiteRepository = Depends(repository),
    service: InvestigationService = Depends(investigation_service),
) -> dict:
    if not repo.get_chain(chain_id):
        raise HTTPException(status_code=404, detail="attack chain not found")
    case_id = "case_%s" % uuid4().hex[:16]
    background.add_task(service.investigate, chain_id, case_id, scope, max_steps)
    return response({
        "case_id": case_id, "chain_id": chain_id, "status": "queued", "scope": scope,
        "max_steps": max_steps,
        "execution_mode": "real_llm" if service.model.configured else "deterministic_fallback",
    })


@router.get("/graph")
def graph_slice(run_id: Optional[str] = None, chain_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository), projector=Depends(graph)) -> dict:
    if chain_id:
        return chain_graph(chain_id, repo, projector)
    allowed_ids = None
    if run_id:
        events = repo.all_events(run_id=run_id)
        detections = repo.all_detections(run_id=run_id)
        allowed_ids = {ref for event in events for ref in [
            event.host.entity_id if event.host else None,
            event.actor.user.entity_id if event.actor.user else None,
            event.actor.process.entity_id if event.actor.process else None,
            event.actor.parent_process.entity_id if event.actor.parent_process else None,
            event.object.ref.entity_id if event.object.ref else None,
        ] if ref}
        allowed_ids.update({ref for detection in detections for ref in detection.entity_ids})
        allowed_ids.update({mapping.subtechnique_id or mapping.technique_id for detection in detections for mapping in detection.attack_mappings})
    nodes = [item for item in projector.entities.values() if allowed_ids is None or item.entity_id in allowed_ids][:100]
    node_ids = {item.entity_id for item in nodes}
    edges = [item for item in projector.relations.values() if item.source_entity_id in node_ids and item.target_entity_id in node_ids][:200]
    return response({"nodes": [item.model_dump(mode="json") for item in nodes], "edges": [item.model_dump(mode="json") for item in edges], "limit": 100, "runtime": projector.status() if hasattr(projector, "status") else {"configured": False, "connected": False, "backend": "memory"}})
