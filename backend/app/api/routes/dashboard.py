from typing import Optional

from fastapi import APIRouter, Depends

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def dashboard(run_id: Optional[str] = None, repo: SQLiteRepository = Depends(repository)) -> dict:
    counts = repo.counts(run_id=run_id)
    aggregates = repo.dashboard_aggregates(run_id=run_id)
    chains = repo.list_chains(5, run_id=run_id)
    return response({
        "counts": counts,
        "sources": aggregates["sources"],
        "recent_chains": [item.model_dump(mode="json") for item in chains],
        "time_quality": aggregates["time_quality"],
    })
