from fastapi import APIRouter, Depends, Request

from app import __version__
from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["system"])


@router.get("/system/health")
def health(request: Request, repo: SQLiteRepository = Depends(repository)) -> dict:
    active = request.app.state.settings
    graph_status = request.app.state.graph.status() if hasattr(request.app.state.graph, "status") else {"configured": False, "connected": False, "backend": "memory"}
    return response({"status": "ok", "version": __version__, "mode": active.mode, "storage": "sqlite", "graph": graph_status, "counts": repo.counts()})


@router.get("/system/version")
def version(request: Request) -> dict:
    return response({"application": __version__, "schema": "1.0", "attack": request.app.state.settings.attack_version})
