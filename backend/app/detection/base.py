from typing import List, Protocol

from app.contracts import DetectionResult, Evidence, Session, UnifiedSecurityEvent


class Detector(Protocol):
    rule_id: str
    version: str

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]: ...

