import json
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from app.analysis import AnalysisTaskService
from app.api.dependencies import graph, repository
from app.api.envelope import response
from app.collectors.envelope import envelope_from_payload
from app.contracts import SourceDescriptor
from app.contracts.common import SourceKind
from app.core.ids import stable_id
from app.core.time import parse_timestamp, utc_now
from app.live import LiveRunService
from app.repositories import SQLiteRepository

router = APIRouter(tags=["live"])


class StartLiveRequest(BaseModel):
    replay_path: Optional[str] = None


class StopLiveRequest(BaseModel):
    run_id: str


class LiveLogRequest(BaseModel):
    run_id: str
    timestamp: Optional[Any] = None
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    source_type: str
    raw_message: Any
    source_id: Optional[str] = None
    dataset: Optional[str] = None


def live_service(request: Request, repo: SQLiteRepository = Depends(repository), projector=Depends(graph)) -> LiveRunService:
    return LiveRunService(request.app.state.settings, repo, projector)


@router.post("/v1/live/start")
def start_live(payload: StartLiveRequest | None = None, service: LiveRunService = Depends(live_service)) -> dict:
    if payload and payload.replay_path:
        raise HTTPException(status_code=400, detail="live replay path is controlled by server configuration")
    return response(service.start())


@router.get("/v1/live/status")
def live_status(run_id: Optional[str] = None, service: LiveRunService = Depends(live_service)) -> dict:
    return response(service.status(run_id))


@router.get("/v1/live/traffic")
def live_traffic(
    run_id: str,
    window_seconds: int = 90,
    bucket_seconds: int = 5,
    repo: SQLiteRepository = Depends(repository),
) -> dict:
    if run_id == "__none__":
        window = max(30, min(window_seconds, 180))
        bucket = max(1, min(bucket_seconds, 30))
        now = utc_now()
        start = now - timedelta(seconds=window)
        bucket_count = int(window / bucket) + 1
        bucket_starts = [start + timedelta(seconds=index * bucket) for index in range(bucket_count)]
        return response({
            "run_id": None,
            "window_seconds": window,
            "bucket_seconds": bucket,
            "categories": [item.strftime("%H:%M:%S") for item in bucket_starts],
            "series": {"network": [0 for _ in bucket_starts], "endpoint": [0 for _ in bucket_starts], "total": [0 for _ in bucket_starts]},
            "eps": 0,
            "recent_events": [],
        })
    if not repo.get_run(run_id):
        raise HTTPException(status_code=404, detail="live run not found")
    window = max(30, min(window_seconds, 180))
    bucket = max(1, min(bucket_seconds, 30))
    now = utc_now()
    start = now - timedelta(seconds=window)
    bucket_count = int(window / bucket) + 1
    bucket_starts = [start + timedelta(seconds=index * bucket) for index in range(bucket_count)]
    network = [0 for _ in bucket_starts]
    endpoint = [0 for _ in bucket_starts]
    total = [0 for _ in bucket_starts]
    events = repo.query_events(run_id=run_id, start_time=start.isoformat(), end_time=now.isoformat(), limit=2000)
    for event in events:
        offset = int((event.event_time - start).total_seconds() // bucket)
        if offset < 0 or offset >= len(bucket_starts):
            continue
        is_network = bool(event.network) or event.action.startswith("network.") or event.source.kind.value == "zeek"
        if is_network:
            network[offset] += 1
        else:
            endpoint[offset] += 1
        total[offset] += 1
    recent_events = []
    for event in repo.query_events(run_id=run_id, limit=12, descending=True):
        src = event.network.src.ip if event.network and event.network.src else None
        dst = event.network.dst.ip if event.network and event.network.dst else None
        recent_events.append({
            "event_id": event.event_id,
            "time": event.event_time.isoformat(),
            "source": event.source.kind.value,
            "action": event.action,
            "severity": event.severity,
            "src": src or (event.host.display_name if event.host and event.host.display_name else event.host.entity_id if event.host else None),
            "dst": dst or (event.object.ref.display_name if event.object.ref and event.object.ref.display_name else event.object.ref.entity_id if event.object.ref else None),
            "message": event.message,
        })
    eps_window = max(min(window, 15), 1)
    eps_start = now - timedelta(seconds=eps_window)
    eps = sum(1 for event in events if event.event_time >= eps_start) / eps_window
    return response({
        "run_id": run_id,
        "window_seconds": window,
        "bucket_seconds": bucket,
        "categories": [item.strftime("%H:%M:%S") for item in bucket_starts],
        "series": {"network": network, "endpoint": endpoint, "total": total},
        "eps": round(eps, 2),
        "recent_events": recent_events,
    })


@router.post("/v1/live/poll")
def live_poll(run_id: Optional[str] = None, service: LiveRunService = Depends(live_service)) -> dict:
    processed = service.poll_once(run_id)
    payload = service.status(run_id)
    payload["processed"] = processed
    return response(payload)


@router.post("/v1/live/stop")
def stop_live(payload: StopLiveRequest, service: LiveRunService = Depends(live_service)) -> dict:
    try:
        return response(service.stop(payload.run_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="live run not found") from exc


@router.post("/ingest/logs/live")
def ingest_live_log(payload: LiveLogRequest, service: LiveRunService = Depends(live_service)) -> dict:
    envelope = _log_envelope(payload)
    result = service.append(payload.run_id, [envelope])
    return response({"run_id": payload.run_id, "accepted_raw": result.accepted_raw, "normalized_events": len(result.events), "detections": len(result.detections), "attack_chains": len(result.chains)})


@router.post("/ingest/pcap/live")
async def ingest_live_pcap(request: Request, run_id: str = Form(...), source_host: Optional[str] = Form(None), source_id: str = Form("manual-pcap"), file: UploadFile = File(...), repo: SQLiteRepository = Depends(repository), projector=Depends(graph)) -> dict:
    content = await file.read()
    target = request.app.state.settings.data_dir / "live_pcap_uploads" / ("%s_%s" % (stable_id("pcap", file.filename or "capture", utc_now().isoformat()), Path(file.filename or "capture.pcap").name))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    task_service = AnalysisTaskService(request.app.state.settings, repo, projector)
    envelopes = []
    for index, record in enumerate(task_service._pcap_payloads(target)):
        dataset = record.pop("_dataset", "zeek.conn")
        source = SourceDescriptor(kind=SourceKind.zeek, product="Zeek", dataset=dataset, sensor_id=source_id, host_hint=source_host or source_id, source_record_id="%s:%d" % (target.name, index))
        ts = record.get("ts")
        envelopes.append(envelope_from_payload(source, record, "json", ts, "upload://%s#%d" % (target.name, index), _parse_or_now(ts), {"collector": "http_pcap_live", "source_id": source_id}))
    if not envelopes:
        source = SourceDescriptor(kind=SourceKind.zeek, product="PCAP Upload", dataset="pcap.raw", sensor_id=source_id, host_hint=source_host, source_record_id=target.name)
        envelopes.append(envelope_from_payload(source, {"pcap_path": str(target), "parser_status": "no_packets_or_unsupported"}, "json", None, "upload://%s" % target.name, utc_now(), {"collector": "http_pcap_live", "source_id": source_id}))
    result = LiveRunService(request.app.state.settings, repo, projector).append(run_id, envelopes)
    return response({"run_id": run_id, "accepted_raw": result.accepted_raw, "normalized_events": len(result.events), "detections": len(result.detections), "attack_chains": len(result.chains)})


def _log_envelope(payload: LiveLogRequest):
    try:
        source_kind = SourceKind(payload.source_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="unsupported source_type: %s" % payload.source_type) from exc
    raw = payload.raw_message
    payload_format = "json" if isinstance(raw, dict) else "text"
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                raw = json.loads(stripped)
                payload_format = "json"
            except json.JSONDecodeError:
                pass
        elif stripped.startswith("<Event"):
            payload_format = "xml"
    source_id = payload.source_id or payload.source_host or payload.source_ip or source_kind.value
    source = SourceDescriptor(kind=source_kind, product=source_kind.value, dataset=payload.dataset, sensor_id=source_id, host_hint=payload.source_host or payload.source_ip, source_record_id=stable_id("live", source_id, payload.timestamp, raw))
    observed = _parse_or_now(payload.timestamp)
    return envelope_from_payload(source, raw, payload_format, payload.timestamp, "http-live://%s/%s" % (payload.run_id, source.source_record_id), observed, {"collector": "http_live", "source_id": source_id})


def _parse_or_now(value: Any):
    if value is None:
        return utc_now()
    try:
        return parse_timestamp(value)
    except (TypeError, ValueError):
        return utc_now()
