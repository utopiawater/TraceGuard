import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import repository
from app.api.envelope import response
from app.repositories import SQLiteRepository

router = APIRouter(tags=["search"])


TYPE_LABELS = {
    "event": "安全事件",
    "detection": "检测结果",
    "evidence": "Evidence",
    "chain": "攻击链",
    "session": "会话",
    "agent": "Agent 调查",
    "report": "报告",
}


def compact(value: str, limit: int = 180) -> str:
    clean = " ".join(value.split())
    return clean if len(clean) <= limit else clean[: limit - 1] + "..."


def load_json(value: str) -> dict[str, Any]:
    try:
        loaded = json.loads(value)
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def snippet(payload: dict[str, Any], term: str, limit: int = 180) -> str:
    text = json.dumps(payload, ensure_ascii=False)
    index = text.lower().find(term.lower())
    if index < 0:
        return compact(text, limit)
    start = max(0, index - 70)
    end = min(len(text), index + len(term) + 90)
    prefix = "..." if start else ""
    suffix = "..." if end < len(text) else ""
    return compact(prefix + text[start:end] + suffix, limit)


def add_result(results: list[dict[str, Any]], kind: str, item_id: str, title: str, subtitle: str, href: str, payload: dict[str, Any], term: str, run_id: Optional[str] = None, timestamp: Optional[str] = None) -> None:
    results.append({
        "type": kind,
        "type_label": TYPE_LABELS[kind],
        "id": item_id,
        "title": title,
        "subtitle": subtitle,
        "href": href,
        "run_id": run_id,
        "timestamp": timestamp,
        "match": snippet(payload, term),
    })


@router.get("/search")
def search(
    q: str = Query(..., min_length=1, max_length=120),
    limit: int = Query(default=40, ge=1, le=100),
    run_id: Optional[str] = None,
    repo: SQLiteRepository = Depends(repository),
) -> dict:
    term = q.strip()
    if not term:
        return response([], ["请输入搜索关键词。"])

    needle = "%" + term.lower() + "%"
    per_kind = max(3, min(20, limit // 5 + 2))
    results: list[dict[str, Any]] = []

    with repo.connect() as connection:
        run_clause = " AND run_id = ?" if run_id else ""
        run_params: list[Any] = [run_id] if run_id else []

        for row in connection.execute(
            "SELECT event_id,run_id,event_time,source_kind,host_id,action,event_type,event_json FROM normalized_events "
            "WHERE (LOWER(event_id) LIKE ? OR LOWER(action) LIKE ? OR LOWER(event_type) LIKE ? OR LOWER(event_json) LIKE ?)"
            f"{run_clause} ORDER BY event_time DESC LIMIT ?",
            (needle, needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = load_json(row["event_json"])
            add_result(
                results, "event", row["event_id"], "%s · %s" % (row["action"], row["event_type"]),
                "%s · %s" % (row["source_kind"], row["host_id"] or "unknown host"),
                "/events", payload, term, row["run_id"], row["event_time"],
            )

        for row in connection.execute(
            "SELECT detection_id,run_id,rule_id,severity,status,created_at,detection_json FROM detections "
            "WHERE (LOWER(detection_id) LIKE ? OR LOWER(rule_id) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(detection_json) LIKE ?)"
            f"{run_clause} ORDER BY created_at DESC LIMIT ?",
            (needle, needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = load_json(row["detection_json"])
            add_result(
                results, "detection", row["detection_id"], payload.get("title") or row["rule_id"],
                "%s · %s · %s" % (row["severity"], row["status"], row["rule_id"]),
                "/incidents", payload, term, row["run_id"], row["created_at"],
            )

        for row in connection.execute(
            "SELECT evidence_id,run_id,kind,source_ref,observed_at,evidence_json FROM evidence "
            "WHERE (LOWER(evidence_id) LIKE ? OR LOWER(kind) LIKE ? OR LOWER(source_ref) LIKE ? OR LOWER(evidence_json) LIKE ?)"
            f"{run_clause} ORDER BY observed_at DESC LIMIT ?",
            (needle, needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = load_json(row["evidence_json"])
            add_result(
                results, "evidence", row["evidence_id"], "%s · %s" % (row["kind"], row["evidence_id"]),
                row["source_ref"], "/chains?evidence=%s" % row["evidence_id"],
                payload, term, row["run_id"], row["observed_at"],
            )

        for row in connection.execute(
            "SELECT chain_id,run_id,status,start_time,score,chain_json FROM attack_chains "
            "WHERE (LOWER(chain_id) LIKE ? OR LOWER(status) LIKE ? OR LOWER(chain_json) LIKE ?)"
            f"{run_clause} ORDER BY start_time DESC LIMIT ?",
            (needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = load_json(row["chain_json"])
            add_result(
                results, "chain", row["chain_id"], payload.get("title") or row["chain_id"],
                "候选状态 %s · 链可信评分 %.0f%%" % (row["status"], float(row["score"]) * 100),
                "/chains?chain=%s" % row["chain_id"], payload, term, row["run_id"], row["start_time"],
            )

        for row in connection.execute(
            "SELECT session_id,run_id,session_type,start_time,host_id,src_ip,dst_ip,session_json FROM sessions "
            "WHERE (LOWER(session_id) LIKE ? OR LOWER(session_type) LIKE ? OR LOWER(host_id) LIKE ? OR LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(session_json) LIKE ?)"
            f"{run_clause} ORDER BY start_time DESC LIMIT ?",
            (needle, needle, needle, needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = load_json(row["session_json"])
            add_result(
                results, "session", row["session_id"], "%s · %s" % (row["session_type"], row["session_id"]),
                "%s → %s" % (row["src_ip"] or row["host_id"] or "?", row["dst_ip"] or "?"),
                "/events", payload, term, row["run_id"], row["start_time"],
            )

        for row in connection.execute(
            "SELECT report_id,case_id,run_id,format,created_at,artifact_ref,evidence_ids_json FROM reports "
            "WHERE (LOWER(report_id) LIKE ? OR LOWER(case_id) LIKE ? OR LOWER(format) LIKE ? OR LOWER(artifact_ref) LIKE ? OR LOWER(evidence_ids_json) LIKE ?)"
            f"{run_clause} ORDER BY created_at DESC LIMIT ?",
            (needle, needle, needle, needle, needle, *run_params, per_kind),
        ).fetchall():
            payload = dict(row)
            add_result(
                results, "report", row["report_id"], "%s 报告 · %s" % (row["format"], row["case_id"]),
                row["artifact_ref"], "/reports", payload, term, row["run_id"], row["created_at"],
            )

        if not run_id:
            for row in connection.execute(
                "SELECT t.task_id,t.case_id,t.agent_role,t.state,t.task_json,r.result_json FROM agent_tasks t "
                "LEFT JOIN agent_results r ON r.task_id=t.task_id "
                "WHERE LOWER(t.task_id) LIKE ? OR LOWER(t.case_id) LIKE ? OR LOWER(t.agent_role) LIKE ? OR LOWER(t.task_json) LIKE ? OR LOWER(COALESCE(r.result_json,'')) LIKE ? "
                "ORDER BY t.rowid DESC LIMIT ?",
                (needle, needle, needle, needle, needle, per_kind),
            ).fetchall():
                task_payload = load_json(row["task_json"])
                result_payload = load_json(row["result_json"] or "{}")
                payload = {"task": task_payload, "result": result_payload}
                add_result(
                    results, "agent", row["task_id"], "%s · %s" % (row["agent_role"], row["state"]),
                    row["case_id"], "/agents?case=%s" % row["case_id"], payload, term,
                )

    results.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return response(results[:limit])
