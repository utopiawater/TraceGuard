import ipaddress
from typing import Any, List, Set

from app.contracts import DetectionResult


class CorrelationEngine:
    """Build connected components only from identifiers already present in detections."""

    version = "1.0.0"
    window_seconds = 1800

    def groups(self, detections: List[DetectionResult]) -> List[List[DetectionResult]]:
        eligible = [item for item in detections if item.event_ids and item.evidence_ids]
        remaining: Set[str] = {item.detection_id for item in eligible}
        by_id = {item.detection_id: item for item in eligible}
        groups: List[List[DetectionResult]] = []
        while remaining:
            seed = remaining.pop()
            component = [by_id[seed]]
            changed = True
            while changed:
                changed = False
                for candidate_id in list(remaining):
                    candidate = by_id[candidate_id]
                    if any(self._linked(candidate, member) for member in component):
                        remaining.remove(candidate_id)
                        component.append(candidate)
                        changed = True
            groups.append(sorted(component, key=lambda item: (item.created_at, item.detection_id)))
        return sorted(groups, key=lambda group: group[0].created_at)

    def _linked(self, left: DetectionResult, right: DetectionResult) -> bool:
        delta = abs((left.created_at - right.created_at).total_seconds())
        if delta > self.window_seconds:
            return False
        if set(left.event_ids) & set(right.event_ids):
            return True
        if set(left.entity_ids) & set(right.entity_ids):
            return True
        if set(left.session_ids) & set(right.session_ids):
            return True
        left_ips = self._ips(left.feature_values)
        right_ips = self._ips(right.feature_values)
        if left_ips and right_ips and left_ips & right_ips:
            return True
        left_network = self._network_terms(left.feature_values)
        right_network = self._network_terms(right.feature_values)
        return bool(left_network and right_network and left_network & right_network)

    def _ips(self, value: Any) -> Set[str]:
        found: Set[str] = set()
        if isinstance(value, dict):
            for item in value.values():
                found.update(self._ips(item))
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                found.update(self._ips(item))
        elif isinstance(value, str):
            candidate = value.strip("[](), ")
            if ":" in candidate and candidate.count(":") == 1:
                candidate = candidate.rsplit(":", 1)[0]
            try:
                found.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                pass
        return found

    def _network_terms(self, value: Any) -> Set[str]:
        terms: Set[str] = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"source_ip", "destination", "destination_ip", "src_ip", "dst_ip", "peer"}:
                    terms.update(self._flatten(item))
                else:
                    terms.update(self._network_terms(item))
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                terms.update(self._network_terms(item))
        return terms

    def _flatten(self, value: Any) -> Set[str]:
        if isinstance(value, dict):
            return {text for item in value.values() for text in self._flatten(item)}
        if isinstance(value, (list, tuple, set)):
            return {text for item in value for text in self._flatten(item)}
        if value is None:
            return set()
        return {str(value).lower()}
