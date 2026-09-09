from typing import Any, List, Optional
from uuid import uuid4

from app.core.settings import settings
from app.core.time import utc_now


def response(data: Any, warnings: Optional[List[str]] = None, next_cursor: Optional[str] = None, total: Optional[int] = None) -> dict:
    meta = {
        "request_id": "req_%s" % uuid4().hex[:16], "schema_version": "1.0",
        "mode": settings.mode, "generated_at": utc_now().isoformat().replace("+00:00", "Z"),
        "next_cursor": next_cursor, "warnings": warnings or [],
    }
    if total is not None:
        meta["total"] = total
    return {
        "data": data,
        "meta": meta,
    }
