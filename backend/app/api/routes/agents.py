from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["agents"])


def _task_view(record: dict) -> dict:
    task, runtime = record["task"], record["runtime"]
    result_wrapper = record.get("result") or {}
    result = result_wrapper.get("result")
    status = result.get("status") if result else task["state"]
    return {
        **task, "status": status, "started_at": runtime.get("started_at"), "finished_at": runtime.get("finished_at"),
        "created_at": runtime.get("created_at"),
        "chain_id": runtime.get("chain_id"), "investigation_id": runtime.get("investigation_id"),
        "model_fallback": runtime.get("model_fallback", False), "error": runtime.get("error"),
        "result": result, "artifact": result_wrapper.get("artifact", {}),
    }


@router.get("/agents")
def agents(repo: SQLiteRepository = Depends(repository)) -> dict:
    grouped: Dict[str, List[dict]] = {}
    for record in repo.list_agent_records(2000):
        view = _task_view(record)
        grouped.setdefault(view["case_id"], []).append(view)
    values = []
    for case_id, tasks in grouped.items():
        root = next((item for item in tasks if item["agent_role"] == "coordinator"), tasks[0])
        findings = [finding for item in tasks if item.get("result") for finding in item["result"].get("findings", [])]
        confidence = sum(item["confidence"] for item in findings) / len(findings) if findings else 0
        statuses = [item["status"] for item in tasks]
        status = "failed" if statuses and all(item == "failed" for item in statuses) else ("partial" if any(item in {"failed", "partial"} for item in statuses) else ("running" if any(item in {"queued", "running"} for item in statuses) else "succeeded"))
        values.append({
            "case_id": case_id, "attack_chain": root.get("chain_id"), "status": status,
            "created_at": root.get("created_at") or root.get("started_at"),
            "started_at": root.get("started_at"), "finished_at": max([item.get("finished_at") or "" for item in tasks]) or None,
            "final_confidence": round(confidence, 4), "task_count": len(tasks),
            "model_fallback": any(item.get("model_fallback") for item in tasks),
        })
    values.sort(key=lambda item: item.get("started_at") or "", reverse=True)
    warnings = [] if values else ["尚未接入 Agent 调查运行记录；请从攻击链页面选择已有链并开始调查。"]
    return response(values, warnings)


@router.get("/agents/{case_id}")
def agent_detail(case_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    tasks = [_task_view(record) for record in repo.list_agent_records(2000) if record["task"]["case_id"] == case_id]
    if not tasks:
        raise HTTPException(status_code=404, detail="agent investigation not found")
    order = {"coordinator": 0, "host": 1, "network": 2, "correlation": 3, "attribution": 4, "report": 5}
    tasks.sort(key=lambda item: order[item["agent_role"]])
    return response({"case_id": case_id, "chain_id": tasks[0].get("chain_id"), "tasks": tasks})


@router.get("/attribution")
def attribution(repo: SQLiteRepository = Depends(repository)) -> dict:
    values = []
    for record in repo.list_agent_records(2000):
        if record["task"]["agent_role"] != "attribution" or not record.get("result"):
            continue
        view = _task_view(record)
        artifact = view["artifact"]
        candidates = artifact.get("candidates") or [{
            "candidate": artifact.get("label", "无法可靠归因"), "similarity": 0,
            "technique_overlap": artifact.get("technique_overlap", []),
            "c2_ioc_evidence": artifact.get("c2_ioc_evidence", []),
            "supporting_evidence": artifact.get("supporting_evidence", []),
            "counter_evidence": artifact.get("counter_evidence", []), "confidence": artifact.get("confidence", 0),
        }]
        for candidate in candidates:
            values.append({"case_id": view["case_id"], "chain_id": view["chain_id"], "status": artifact.get("status"), **candidate})
    return response(values, [] if values else ["尚无 Attribution Agent 的真实运行结果。"])


@router.get("/reports")
def reports(limit: int = Query(default=100, ge=1, le=500), repo: SQLiteRepository = Depends(repository)) -> dict:
    values = []
    records = repo.list_agent_records(2000)
    for item in repo.list_reports(limit):
        chain_id = next((record["runtime"].get("chain_id") for record in records if record["task"]["case_id"] == item["case_id"] and record["runtime"].get("chain_id")), None)
        values.append({**item, "attack_chain": chain_id, "agent_investigation": item["case_id"], "view_url": "/api/reports/%s" % item["report_id"], "export_url": "/api/reports/%s/export" % item["report_id"]})
    return response(values, [] if values else ["尚无 Report Agent 持久化的真实报告。"])


@router.get("/reports/{report_id}")
def report_detail(report_id: str, repo: SQLiteRepository = Depends(repository)) -> dict:
    item = repo.get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(item["artifact_ref"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="report artifact is unavailable")
    records = repo.list_agent_records(2000)
    chain_id = next((record["runtime"].get("chain_id") for record in records if record["task"]["case_id"] == item["case_id"] and record["runtime"].get("chain_id")), None)
    sections = next((record["result"].get("artifact", {}).get("sections") for record in records if record["task"]["case_id"] == item["case_id"] and record["task"]["agent_role"] == "report" and record.get("result")), None)
    return response({**item, "attack_chain": chain_id, "agent_investigation": item["case_id"], "sections": sections, "content": path.read_text(encoding="utf-8"), "export_url": "/api/reports/%s/export" % report_id})


@router.get("/reports/{report_id}/export")
def export_report(report_id: str, repo: SQLiteRepository = Depends(repository)):
    item = repo.get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(item["artifact_ref"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="report artifact is unavailable")
    media = "text/markdown" if item["format"] == "markdown" else "text/html"
    return FileResponse(str(path), media_type=media, filename=path.name)
