from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import api_router
from app.api.openapi import install_contract_openapi
from app.core.settings import Settings, settings as default_settings
from app.graph import RuntimeGraphProjector
from app.entities import EntityResolver
from app.repositories import SQLiteRepository
from app.agents.service import InvestigationService


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    active = settings or default_settings
    active.ensure_directories()
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        yield
        application.state.graph.close()

    app = FastAPI(title="TraceGuard API", version="0.1.0", description="Evidence-first multi-source attack tracing API", lifespan=lifespan)
    app.state.settings = active
    app.state.repository = SQLiteRepository(active.database_path)
    app.state.graph = RuntimeGraphProjector(active.neo4j_uri, active.neo4j_user, active.neo4j_password, active.neo4j_enabled, Path(__file__).parents[2] / "deploy" / "neo4j" / "schema.cypher")
    startup_projection = EntityResolver().resolve(
        app.state.repository.all_events(),
        app.state.repository.all_sessions(),
        app.state.repository.all_detections(),
    )
    if hasattr(app.state.graph, "memory"):
        app.state.graph.memory.project(startup_projection)
    else:
        app.state.graph.project(startup_projection)
    app.state.investigation_service = InvestigationService(app.state.repository, app.state.graph, active)
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=False, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])
    app.include_router(api_router)
    install_contract_openapi(app)
    return app


app = create_app()
