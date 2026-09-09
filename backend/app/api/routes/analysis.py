from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from app.analysis import AnalysisTaskService
from app.api.dependencies import graph, repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(prefix="/v1/analysis", tags=["analysis"])


def analysis_service(request: Request, repo: SQLiteRepository = Depends(repository), projector=Depends(graph)) -> AnalysisTaskService:
    return AnalysisTaskService(request.app.state.settings, repo, projector)


@router.post("/upload")
async def upload(file: UploadFile = File(...), service: AnalysisTaskService = Depends(analysis_service)) -> dict:
    content = await file.read()
    try:
        task = service.create_from_upload(file.filename or "upload.bin", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return response(task, task.get("identification", {}).get("warnings", []))


@router.post("/tasks/{task_id}/start")
def start(task_id: str, service: AnalysisTaskService = Depends(analysis_service)) -> dict:
    try:
        task = service.start(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="analysis task not found") from exc
    return response(task, task.get("identification", {}).get("warnings", []))


@router.get("/tasks/{task_id}")
def task(task_id: str, service: AnalysisTaskService = Depends(analysis_service)) -> dict:
    try:
        item = service.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="analysis task not found") from exc
    return response(item, item.get("identification", {}).get("warnings", []))


@router.get("/tasks/{task_id}/result")
def result(task_id: str, service: AnalysisTaskService = Depends(analysis_service)) -> dict:
    try:
        item = service.result(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="analysis task not found") from exc
    return response(item, item.get("task", {}).get("identification", {}).get("warnings", []))


@router.get("/tasks")
def tasks(service: AnalysisTaskService = Depends(analysis_service)) -> dict:
    return response(service.list())
