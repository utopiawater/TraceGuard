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
    llm_configured = bool(active.llm_base_url and active.llm_api_key and active.llm_model)
    return response({
        "status": "ok", "version": __version__, "mode": active.mode, "storage": "sqlite",
        "graph": graph_status, "counts": repo.counts(),
        "llm": {
            "configured": llm_configured,
            "execution_mode": "real_llm" if llm_configured else "deterministic_fallback",
            "model": active.llm_model or None,
            "timeout_seconds": active.llm_timeout_seconds,
        },
    })


@router.get("/system/version")
def version(request: Request) -> dict:
    return response({"application": __version__, "schema": "1.0", "attack": request.app.state.settings.attack_version})
