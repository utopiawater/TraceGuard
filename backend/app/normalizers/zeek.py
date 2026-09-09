from typing import Any, Dict, List

from app.contracts import NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import asset_aliases, default_timezone, domain_ref, file_ref, host_ref, ip_ref, provenance


class ZeekAdapter:
    name = "zeek"
    version = "1.2.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.zeek

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, dict):
            raise AdapterError("Zeek adapter expects JSON log records")
        row: Dict[str, Any] = raw.payload
        dataset = raw.source.dataset or "zeek.conn"
        if dataset not in {"zeek.conn", "zeek.dns", "zeek.http", "zeek.files", "zeek.weird", "zeek.notice", "zeek.icmp"}:
            return []
        ts = parse_timestamp(row.get("ts") or raw.event_time_raw or raw.observed_time.isoformat(), default_timezone(raw))
        uid = row.get("uid")
        tx_hosts = row.get("tx_hosts") or []
        rx_hosts = row.get("rx_hosts") or []
        src_ip = row.get("id.orig_h") or row.get("src") or (tx_hosts[0] if tx_hosts else None)
        dst_ip = row.get("id.resp_h") or row.get("dst") or (rx_hosts[0] if rx_hosts else None)
        if not src_ip or not dst_ip:
            raise AdapterError("Zeek record is missing id.orig_h/id.resp_h")
        action = {"zeek.conn": "network.flow", "zeek.dns": "dns.query", "zeek.http": "http.request", "zeek.files": "network.file_transfer", "zeek.weird": "network.anomaly", "zeek.notice": "security.notice", "zeek.icmp": "icmp.message"}[dataset]
        app = row.get("service") or dataset.split(".")[-1]
        if app not in {"dns", "http", "https", "ssh", "smb", "rdp", "smtp"}:
            app = "other"
        host = host_ref(raw.source.host_hint or src_ip, raw.source.sensor_id, asset_aliases(raw))
        session_id = stable_id("session", raw.source.sensor_id, uid) if uid else stable_id("session", raw.source.sensor_id, src_ip, row.get("id.orig_p"), dst_ip, row.get("id.resp_p"), int(ts.timestamp()))
        transport = (row.get("proto") or ("icmp" if dataset == "zeek.icmp" else "other")).lower()
        if transport not in {"tcp", "udp", "icmp", "other"}: transport = "other"
        context = NetworkContext(
            session_id=session_id, direction="outbound", transport=transport, application=app,
            src=NetworkEndpoint(ip=src_ip, port=int(row["id.orig_p"]) if row.get("id.orig_p") is not None else None, host_id=host.entity_id),
            dst=NetworkEndpoint(ip=dst_ip, port=int(row["id.resp_p"]) if row.get("id.resp_p") is not None else None),
            bytes_sent=int(row.get("orig_bytes", 0) or 0), bytes_received=int(row.get("resp_bytes", 0) or 0),
            packets_sent=int(row.get("orig_pkts", 0) or 0), packets_received=int(row.get("resp_pkts", 0) or 0),
            duration_ms=float(row.get("duration", 0) or 0) * 1000, zeek_uid=uid,
            dns=row if dataset == "zeek.dns" else None, http=row if dataset == "zeek.http" else None,
            icmp=row if dataset == "zeek.icmp" or transport == "icmp" else None,
        )
        object_ref = ip_ref(dst_ip)
        object_type = "network"
        if dataset == "zeek.dns":
            object_ref = domain_ref(row.get("query")) or object_ref
        elif dataset == "zeek.files":
            object_type = "file"
            object_ref = file_ref(host.entity_id, row.get("filename") or row.get("fuid"))
        return [UnifiedSecurityEvent(
            event_id=stable_id("evt", raw.source.kind.value, raw.source.sensor_id, raw.source_record_id, raw.raw_id, 0),
            event_time=ts, observed_time=raw.observed_time, ingested_time=raw.ingested_time,
            time=TimeContext(original=raw.event_time_raw, uncertainty_ms=5, quality="synced"), source=raw.source, host=host,
            object=ObjectContext(type=object_type, ref=object_ref), network=context, action=action, event_type=dataset,
            outcome="success", severity="low" if dataset in {"zeek.notice", "zeek.weird"} else "informational", message="%s %s:%s → %s:%s" % (transport, src_ip, row.get("id.orig_p", "?"), dst_ip, row.get("id.resp_p", "?")),
            tags=["network", "zeek"], extensions={"zeek": row}, provenance=provenance(raw, self.name, self.version),
        )]
