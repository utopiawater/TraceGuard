from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["events"])


@router.get("/events")
def events(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    return response([item.model_dump(mode="json") for item in repo.list_events(limit, run_id=run_id, offset=offset)], total=repo.count_table("normalized_events", run_id=run_id))


@router.get("/events/{event_id}")
def event_detail(event_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    item = repo.get_event(event_id)
    if not item:
        raise HTTPException(status_code=404, detail="event not found")
    return response(item.model_dump(mode="json"))


@router.get("/sessions")
def sessions(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    return response([item.model_dump(mode="json") for item in repo.list_sessions(limit, run_id=run_id, offset=offset)], total=repo.count_table("sessions", run_id=run_id))


@router.get("/evidence")
def evidence(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    return response([item.model_dump(mode="json") for item in repo.list_evidence(limit, run_id=run_id, offset=offset)], total=repo.count_table("evidence", run_id=run_id))


@router.get("/evidence/{evidence_id}")
def evidence_detail(evidence_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    item = repo.get_evidence(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="evidence not found")
    return response(item.model_dump(mode="json"))
