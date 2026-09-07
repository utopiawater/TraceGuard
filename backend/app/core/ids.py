import hashlib
import json
from typing import Any


def stable_id(prefix: str, *parts: Any) -> str:
    canonical = "|".join(
        json.dumps(part, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        for part in parts
    )
    return "%s_%s" % (prefix, hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24])


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

