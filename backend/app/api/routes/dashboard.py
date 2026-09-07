from fastapi import APIRouter, Depends

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def dashboard(repo: SQLiteRepository = Depends(repository)) -> dict:
    counts = repo.counts()
    events = repo.list_events(500)
    chains = repo.list_chains(5)
    source_summary = {}
    for event in events:
        item = source_summary.setdefault(event.source.kind.value, {"source": event.source.kind.value, "event_count": 0, "last_event_time": None, "status": "healthy"})
        item["event_count"] += 1
        item["last_event_time"] = event.event_time.isoformat()
    return response({
        "counts": counts,
        "sources": list(source_summary.values()),
        "recent_chains": [item.model_dump(mode="json") for item in chains],
        "time_quality": {"synced": sum(1 for item in events if item.time.quality == "synced"), "other": sum(1 for item in events if item.time.quality != "synced")},
    })

