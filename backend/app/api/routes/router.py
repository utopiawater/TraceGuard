from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .collectors import router as collectors_router
from .events import router as events_router
from .investigation import router as investigation_router
from .resources import router as resources_router
from .system import router as system_router
from .agents import router as agents_router

api_router = APIRouter(prefix="/api")
for router in (dashboard_router, collectors_router, events_router, investigation_router, resources_router, agents_router, system_router):
    api_router.include_router(router)
