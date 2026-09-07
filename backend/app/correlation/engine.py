from typing import List, Set

from app.contracts import DetectionResult


class CorrelationEngine:
    """Build connected components only from identifiers already present in detections."""

    version = "1.0.0"
    window_seconds = 1800

    def groups(self, detections: List[DetectionResult]) -> List[List[DetectionResult]]:
        eligible = [item for item in detections if item.event_ids and item.entity_ids and item.evidence_ids and item.attack_mappings]
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
        return bool(set(left.event_ids) & set(right.event_ids) or set(left.entity_ids) & set(right.entity_ids) or set(left.session_ids) & set(right.session_ids))
