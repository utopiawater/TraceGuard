import re
from typing import Any, Dict, List

from app.contracts import NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .helpers import asset_aliases, default_timezone, domain_ref, host_ref, ip_ref, provenance


NGINX_RE = re.compile(
    r'(?P<src>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+) HTTP/(?P<version>[^"]+)" (?P<status>\d{3}) (?P<body_bytes>\S+)(?: "[^"]*" "(?P<ua>[^"]*)")?'
)


class ApplicationWebAdapter:
    name = "application-web"
    version = "1.0.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.application and (raw.source.dataset or "").startswith(("web.", "c2."))

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        rows = self._rows(raw.payload)
        events: List[UnifiedSecurityEvent] = []
        for index, row in enumerate(rows):
            ts = parse_timestamp(row.get("timestamp") or row.get("time") or raw.event_time_raw or raw.observed_time.isoformat(), default_timezone(raw))
            host_header = row.get("host") or row.get("domain") or row.get("server_name")
            src_ip = row.get("src_ip") or row.get("remote_addr") or row.get("client_ip")
            dst_ip = row.get("dst_ip") or row.get("server_ip")
            host = host_ref(raw.source.host_hint or host_header or raw.source.sensor_id, raw.source.sensor_id, asset_aliases(raw))
            dst_port = self._port(row.get("dst_port") or row.get("server_port") or (443 if str(row.get("scheme")).lower() == "https" else 80))
            src_port = self._port(row.get("src_port") or row.get("client_port"))
            session_id = stable_id("session", raw.source.sensor_id, src_ip, src_port, dst_ip or host_header, dst_port, index)
            http = {
                "host": host_header,
                "uri": row.get("uri") or row.get("path") or row.get("url") or "/",
                "method": row.get("method") or row.get("request_method") or "GET",
                "status_code": row.get("status") or row.get("status_code"),
                "user_agent": row.get("user_agent") or row.get("ua"),
                "request_body_len": self._int(row.get("request_body_len") or row.get("bytes_sent") or 0),
            }
            network = NetworkContext(
                session_id=session_id,
                direction="inbound",
                transport="tcp",
                application="https" if dst_port == 443 else "http",
                src=NetworkEndpoint(ip=src_ip, port=src_port),
                dst=NetworkEndpoint(ip=dst_ip, port=dst_port, host_id=host.entity_id),
                bytes_sent=self._int(row.get("request_body_len") or row.get("bytes_sent")),
                bytes_received=self._int(row.get("body_bytes") or row.get("bytes_received")),
                http=http,
            )
            object_ref = domain_ref(host_header) or (ip_ref(dst_ip) if dst_ip else None)
            events.append(UnifiedSecurityEvent(
                event_id=stable_id("evt", raw.source.kind.value, raw.source.sensor_id, raw.raw_id, index),
                event_time=ts,
                observed_time=raw.observed_time,
                ingested_time=raw.ingested_time,
                time=TimeContext(original=row.get("timestamp") or row.get("time") or raw.event_time_raw, uncertainty_ms=1000, quality="estimated"),
                source=raw.source,
                host=host,
                object=ObjectContext(type="network", ref=object_ref),
                network=network,
                action="http.request",
                event_type=raw.source.dataset or "web.http",
                outcome="success" if str(http.get("status_code") or "200").startswith(("2", "3")) else "failure",
                severity="informational",
                message="%s %s %s" % (http["method"], http["uri"], host_header or ""),
                tags=["web", "http"],
                extensions={"web": row},
                provenance=provenance(raw, self.name, self.version),
            ))
        return events

    def _rows(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, dict):
            return [payload]
        text = str(payload or "")
        rows = []
        for line in text.splitlines():
            match = NGINX_RE.search(line.strip())
            if not match:
                continue
            rows.append({
                "remote_addr": match.group("src"),
                "time": match.group("time"),
                "method": match.group("method"),
                "uri": match.group("uri"),
                "status": match.group("status"),
                "body_bytes": None if match.group("body_bytes") == "-" else match.group("body_bytes"),
                "user_agent": match.group("ua"),
            })
        return rows

    @staticmethod
    def _int(value: Any):
        if value in {None, "", "-"}:
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _port(value: Any):
        try:
            return int(value) if value not in {None, "", "-"} else None
        except (TypeError, ValueError):
            return None
