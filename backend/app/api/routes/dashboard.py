from typing import Optional

from fastapi import APIRouter, Depends

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def dashboard(run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    counts = repo.counts()
    events = repo.list_events(500, run_id=run_id)
    chains = repo.list_chains(5, run_id=run_id)
    if run_id:
        counts = {
            **counts,
            "normalized_events": len(repo.query_events(run_id=run_id, limit=50000)),
            "sessions": len(repo.query_sessions(run_id=run_id, limit=50000)),
            "evidence": len(repo.list_evidence(50000, run_id=run_id)),
            "detections": len(repo.list_detections(50000, run_id=run_id)),
            "attack_chains": len(repo.list_chains(50000, run_id=run_id)),
        }
    source_summary = {}
    for event in events:
        item = source_summary.setdefault(event.source.kind.value, {"source": event.source.kind.value, "event_count": 0, "last_event_time": None, "status": "ingested"})
        item["event_count"] += 1
        item["last_event_time"] = event.event_time.isoformat()
    return response({
        "counts": counts,
        "sources": list(source_summary.values()),
        "recent_chains": [item.model_dump(mode="json") for item in chains],
        "time_quality": {"synced": sum(1 for item in events if item.time.quality == "synced"), "other": sum(1 for item in events if item.time.quality != "synced")},
    })
