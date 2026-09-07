import math
from collections import Counter, defaultdict
from statistics import mean, pstdev
from typing import Dict, List, Tuple

from app.contracts import DetectionResult, Evidence, Session, UnifiedSecurityEvent
from app.core.ids import stable_id


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log(count / size, 2) for count in counts.values())


def _evidence(event_ids: List[str], values: List[Evidence]) -> List[str]:
    wanted = set(event_ids)
    return sorted({item.evidence_id for item in values if wanted.intersection(item.event_ids)})


def _periodicity(times: List[float]) -> Tuple[float, float]:
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    if not gaps:
        return 0.0, 1.0
    avg = mean(gaps)
    return avg, (pstdev(gaps) / avg if len(gaps) > 1 and avg else 1.0)


class DnsTunnelRule:
    rule_id = "det.network.dns_tunnel"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        groups: Dict[str, List[Tuple[UnifiedSecurityEvent, str]]] = defaultdict(list)
        for event in events:
            if event.action != "dns.query" or not event.network or not event.network.dns:
                continue
            query = str(event.network.dns.get("query") or event.network.dns.get("QueryName") or "").rstrip(".").lower()
            parts = query.split(".")
            if len(parts) >= 2:
                groups[".".join(parts[-2:])].append((event, parts[0]))
        results = []
        for domain, items in groups.items():
            labels = [label for _, label in items]
            entropies = [_entropy(label) for label in labels]
            unique_ratio = len(set(labels)) / len(labels)
            nxdomain_ratio = sum(str(event.network.dns.get("rcode_name") or event.network.dns.get("rcode") or "").upper() in {"NXDOMAIN", "3"} for event, _ in items) / len(items)
            features = {"query_count": len(items), "base_domain": domain, "average_label_length": round(mean(map(len, labels)), 2), "max_label_length": max(map(len, labels)), "average_entropy": round(mean(entropies), 3), "unique_ratio": round(unique_ratio, 3), "nxdomain_ratio": round(nxdomain_ratio, 3)}
            score = min(1.0, 0.18 * min(len(items) / 4, 1) + 0.25 * min(features["average_label_length"] / 32, 1) + 0.27 * min(features["average_entropy"] / 4.5, 1) + 0.2 * unique_ratio + 0.1 * nxdomain_ratio)
            if len(items) < 3 or features["average_label_length"] < 20 or features["average_entropy"] < 3.2 or score < 0.68:
                continue
            event_ids = [event.event_id for event, _ in items]
            entity_ids = sorted({ref.entity_id for event, _ in items for ref in (event.host, event.object.ref) if ref})
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, domain, event_ids), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="DNS 隐蔽信道特征", detector_type="statistical", severity="high", confidence=round(score, 3), event_ids=event_ids, entity_ids=entity_ids, session_ids=sorted({event.network.session_id for event, _ in items if event.network.session_id}), feature_values=features, reason="同一基础域名出现高熵、长且高唯一率的子域序列，符合分块编码传输特征。", attack_mappings=[], evidence_ids=_evidence(event_ids, evidence), created_at=max(event.event_time for event, _ in items)))
        return results


class HttpCovertChannelRule:
    rule_id = "det.network.http_covert_channel"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        groups: Dict[str, List[UnifiedSecurityEvent]] = defaultdict(list)
        for event in events:
            if event.action == "http.request" and event.network and event.network.http:
                host = str(event.network.http.get("host") or event.network.dst.ip or "unknown").lower()
                groups[host].append(event)
        results = []
        for host, items in groups.items():
            items.sort(key=lambda item: item.event_time)
            uris = [str(item.network.http.get("uri") or "") for item in items]
            avg_gap, gap_cv = _periodicity([item.event_time.timestamp() for item in items])
            avg_entropy = mean(_entropy(uri) for uri in uris)
            upload_bytes = sum(int(item.network.http.get("request_body_len") or item.network.bytes_sent or 0) for item in items)
            features = {"request_count": len(items), "host": host, "average_uri_length": round(mean(map(len, uris)), 2), "average_uri_entropy": round(avg_entropy, 3), "average_interval_seconds": round(avg_gap, 3), "interval_cv": round(gap_cv, 3), "upload_bytes": upload_bytes, "methods": sorted({str(item.network.http.get("method") or "GET") for item in items})}
            score = min(1.0, 0.2 * min(len(items) / 4, 1) + 0.25 * min(features["average_uri_length"] / 80, 1) + 0.25 * min(avg_entropy / 4.5, 1) + 0.15 * (1 - min(gap_cv, 1)) + 0.15 * min(upload_bytes / 4096, 1))
            if len(items) < 3 or features["average_uri_length"] < 45 or avg_entropy < 3.4 or score < 0.65:
                continue
            event_ids = [item.event_id for item in items]
            entity_ids = sorted({ref.entity_id for item in items for ref in (item.host, item.object.ref) if ref})
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, host, event_ids), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="HTTP 隐蔽信道特征", detector_type="statistical", severity="high", confidence=round(score, 3), event_ids=event_ids, entity_ids=entity_ids, session_ids=sorted({item.network.session_id for item in items if item.network.session_id}), feature_values=features, reason="长高熵 URI、规律请求间隔和持续上传共同指向 HTTP 编码信道。", attack_mappings=[], evidence_ids=_evidence(event_ids, evidence), created_at=items[-1].event_time))
        return results


class IcmpTunnelRule:
    rule_id = "det.network.icmp_tunnel"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        groups: Dict[str, List[UnifiedSecurityEvent]] = defaultdict(list)
        for event in events:
            if event.network and event.network.transport == "icmp" and event.network.icmp:
                groups["%s>%s" % (event.network.src.ip, event.network.dst.ip)].append(event)
        results = []
        for pair, items in groups.items():
            items.sort(key=lambda item: item.event_time)
            lengths = [int(item.network.icmp.get("payload_len") or item.network.icmp.get("len") or item.network.bytes_sent or 0) for item in items]
            entropies = [float(item.network.icmp.get("payload_entropy") or _entropy(str(item.network.icmp.get("payload") or ""))) for item in items]
            avg_gap, gap_cv = _periodicity([item.event_time.timestamp() for item in items])
            features = {"message_count": len(items), "peer_pair": pair, "average_payload_length": round(mean(lengths), 2), "average_payload_entropy": round(mean(entropies), 3), "average_interval_seconds": round(avg_gap, 3), "interval_cv": round(gap_cv, 3)}
            score = min(1.0, 0.2 * min(len(items) / 4, 1) + 0.3 * min(features["average_payload_length"] / 64, 1) + 0.3 * min(features["average_payload_entropy"] / 5, 1) + 0.2 * (1 - min(gap_cv, 1)))
            if len(items) < 4 or features["average_payload_length"] < 32 or features["average_payload_entropy"] < 3.3 or score < 0.65:
                continue
            event_ids = [item.event_id for item in items]
            entity_ids = sorted({ref.entity_id for item in items for ref in (item.host, item.object.ref) if ref})
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, pair, event_ids), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="ICMP 隐蔽信道特征", detector_type="statistical", severity="high", confidence=round(score, 3), event_ids=event_ids, entity_ids=entity_ids, session_ids=sorted({item.network.session_id for item in items if item.network.session_id}), feature_values=features, reason="ICMP 负载持续偏大、高熵且时间间隔稳定，超出常规探测流量特征。", attack_mappings=[], evidence_ids=_evidence(event_ids, evidence), created_at=items[-1].event_time))
        return results
