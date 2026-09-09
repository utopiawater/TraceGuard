import os
from datetime import datetime, timedelta, timezone
import re
from typing import Optional, Union


MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timezone_from_string(value: Optional[str]) -> timezone:
    if not value:
        return timezone.utc
    normalized = value.strip()
    if normalized.upper() in {"UTC", "Z", "+00:00", "+0000"}:
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", normalized)
    if not match:
        return timezone.utc
    sign = 1 if match.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))


def _default_timezone(value: Optional[str]) -> timezone:
    return timezone_from_string(value or os.getenv("TRACEGUARD_DEFAULT_TIMEZONE"))


def parse_timestamp(value: Union[str, int, float], default_timezone: Optional[str] = None) -> datetime:
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
    apache_match = re.fullmatch(
        r"(?P<day>\d{1,2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4})[: ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?: (?P<tz>[+-]\d{4}))?",
        normalized,
    )
    if apache_match:
        month = MONTHS.get(apache_match.group("month").lower())
        if month:
            parsed = datetime(
                int(apache_match.group("year")),
                month,
                int(apache_match.group("day")),
                int(apache_match.group("hour")),
                int(apache_match.group("minute")),
                int(apache_match.group("second")),
                tzinfo=_default_timezone(default_timezone),
            )
            tz_value = apache_match.group("tz")
            if tz_value:
                offset_hours = int(tz_value[:3])
                offset_minutes = int(tz_value[0] + tz_value[3:])
                parsed = parsed.replace(tzinfo=timezone(timedelta(hours=offset_hours, minutes=offset_minutes)))
            return parsed.astimezone(timezone.utc)
    for pattern in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y %H:%M:%S %z", "%d/%b/%Y %H:%M:%S"):
        try:
            parsed = datetime.strptime(normalized, pattern)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=_default_timezone(default_timezone))
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
        parsed = parsed.replace(tzinfo=_default_timezone(default_timezone))
    return parsed.astimezone(timezone.utc)
