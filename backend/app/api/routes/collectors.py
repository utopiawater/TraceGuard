from pathlib import Path

from fastapi import APIRouter, Request

from app.api.envelope import response
from app.collectors import LinuxAuditCollector, ReplayCollector, WindowsEventCollector, ZeekCollector

router = APIRouter(tags=["collectors"])


def configured_collectors(project_root: Path):
    fixtures = project_root / "backend" / "fixtures" / "collectors"
    return [
        WindowsEventCollector(fixtures / "windows_events.json"),
        LinuxAuditCollector(fixtures / "audit.log"),
        ZeekCollector(fixtures / "zeek"),
        ReplayCollector(project_root / "datasets" / "sample_attack_dataset.json"),
    ]


@router.get("/collectors/status")
def collector_status(request: Request) -> dict:
    project_root = Path(__file__).resolve().parents[4]
    statuses = [collector.health_check().__dict__ for collector in configured_collectors(project_root)]
    return response(statuses)
