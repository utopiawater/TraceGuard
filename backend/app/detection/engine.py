from typing import List

from app.contracts import DetectionResult, Evidence, Session, UnifiedSecurityEvent
from app.knowledge.attack import AttackMappingRegistry

from .registry import RuleRegistry


class DetectionEngine:
    version = "1.0.0"

    def __init__(self, registry: RuleRegistry, mappings: AttackMappingRegistry) -> None:
        self.registry = registry
        self.mappings = mappings

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        for rule in self.registry.all():
            for detection in rule.evaluate(run_id, events, sessions, evidence):
                detection.attack_mappings = self.mappings.for_detection(detection.rule_id)
                results.append(detection)
        return sorted(results, key=lambda item: (item.created_at, item.detection_id))

