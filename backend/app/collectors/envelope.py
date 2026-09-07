import json
from datetime import datetime
from typing import Any, Dict, Optional, Union

from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.ids import sha256_text, stable_id
from app.core.time import utc_now


def envelope_from_payload(
    source: SourceDescriptor,
    payload: Union[Dict[str, Any], str],
    payload_format: str,
    event_time_raw: Optional[Union[str, float, int]],
    raw_ref: str,
    observed_time: Optional[datetime] = None,
    labels: Optional[Dict[str, Any]] = None,
) -> RawEventEnvelope:
    canonical = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = sha256_text(canonical)
    raw_id = stable_id("raw", source.sensor_id, source.source_record_id, digest)
    seen = observed_time or utc_now()
    return RawEventEnvelope(
        raw_id=raw_id,
        source=source,
        source_record_id=source.source_record_id,
        event_time_raw=event_time_raw,
        observed_time=seen,
        ingested_time=seen,
        payload_format=payload_format,
        payload=payload,
        raw_ref=raw_ref,
        raw_sha256=digest,
        labels=labels or {},
    )

