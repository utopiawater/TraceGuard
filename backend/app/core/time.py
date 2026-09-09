from datetime import datetime, timezone
import re
from typing import Union


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Union[str, int, float]) -> datetime:
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds = seconds / 1000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    normalized = value.strip()
    if not normalized:
        raise ValueError("empty timestamp")
    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        return parse_timestamp(float(normalized))
    for pattern in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y %H:%M:%S %z", "%d/%b/%Y %H:%M:%S"):
        try:
            parsed = datetime.strptime(normalized, pattern)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    normalized = re.sub(r"(\.\d{6})\d+(?=[+-]\d\d:\d\d$)", r"\1", normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("unsupported timestamp format: %r" % value) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
