from typing import List

from app.contracts import AttackChain, AttackMapping, ChainStep, DetectionResult
from app.contracts.analytics import ChainStepRef, StepPredecessor
from app.core.ids import stable_id
from app.correlation import CorrelationEngine


TACTIC_STAGE = {"TA0001": "initial_access", "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege_escalation", "TA0006": "credential_access", "TA0007": "discovery", "TA0008": "lateral_movement", "TA0009": "collection", "TA0011": "command_and_control", "TA0010": "exfiltration"}
MAINLINE = {"initial_access", "execution", "command_and_control", "lateral_movement", "privilege_escalation", "collection", "exfiltration"}
SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INFERRED_MAPPINGS = {
    "det.auth.remote_interactive_logon": AttackMapping(technique_id="T1078", tactic_ids=["TA0001"], mapping_rule_id="chain.infer.valid_accounts", attack_version="19.2", confidence=0.62),
    "det.host.privilege_escalation": AttackMapping(technique_id="T1068", tactic_ids=["TA0004"], mapping_rule_id="chain.infer.privilege_escalation", attack_version="19.2", confidence=0.68),
}


class DeterministicChainBuilder:
    version = "1.1.0"

    def __init__(self, correlation=None):
        self.correlation = correlation or CorrelationEngine()

    def build(self, run_id: str, detections: List[DetectionResult]) -> List[AttackChain]:
        groups = self.correlation.groups(detections)
        chains = []
        for group in groups:
            if any(self._mapping(item) and TACTIC_STAGE.get(self._mapping(item).tactic_ids[0]) in MAINLINE for item in group):
                chain = self._build_group(run_id, group)
                if chain.steps:
                    chains.append(chain)
        return chains

    def _build_group(self, run_id: str, eligible: List[DetectionResult]) -> AttackChain:
        eligible.sort(key=lambda item: (item.created_at, SEVERITY_ORDER[item.severity], item.detection_id))
        representatives: dict[str, DetectionResult] = {}
        for detection in eligible:
            mapping = self._mapping(detection)
            if not mapping:
                continue
            tactic = mapping.tactic_ids[0]
            stage = TACTIC_STAGE.get(tactic, "execution")
            if stage not in MAINLINE:
                continue
            current = representatives.get(stage)
            if current is None or self._stage_representative_key(detection) > self._stage_representative_key(current):
                representatives[stage] = detection
        eligible = sorted(representatives.values(), key=lambda item: (item.created_at, SEVERITY_ORDER[item.severity], item.detection_id))
        steps: List[ChainStep] = []
        for index, detection in enumerate(eligible):
            mapping = self._mapping(detection)
            if not mapping:
                continue
            tactic_id = mapping.tactic_ids[0]
            technique_id = mapping.subtechnique_id or mapping.technique_id
            step_id = stable_id("step", detection.detection_id, technique_id)
            predecessors = []
            if steps:
                shared = sorted(set(steps[-1].entity_ids).intersection(detection.entity_ids))
                relation = self._predecessor_relation(steps[-1], detection, shared)
                predecessors = [StepPredecessor(
                    step_id=steps[-1].step_id,
                    relation=relation,
                    score=0.88 if shared else 0.68,
                    evidence_ids=sorted(set(steps[-1].evidence_ids + detection.evidence_ids)),
                )]
            steps.append(ChainStep(
                step_id=step_id, stage=TACTIC_STAGE.get(tactic_id, "execution"), tactic_id=tactic_id,
                technique_id=technique_id, event_ids=detection.event_ids, detection_ids=[detection.detection_id],
                entity_ids=detection.entity_ids, session_ids=detection.session_ids, predecessors=predecessors,
                start_time=detection.created_at, end_time=detection.created_at,
                score=round(detection.confidence * mapping.confidence, 3), evidence_ids=detection.evidence_ids,
                explanation=detection.reason,
            ))
        all_evidence = sorted({value for step in steps for value in step.evidence_ids})
        all_entities = sorted({value for step in steps for value in step.entity_ids})
        techniques = [step.technique_id for step in steps]
        mean_score = sum(step.score for step in steps) / len(steps)
        chain_id = stable_id("chain", run_id, [item.detection_id for item in eligible])
        expected = {"initial_access", "execution", "command_and_control", "lateral_movement", "privilege_escalation", "collection", "exfiltration"}
        covered = set(step.stage for step in steps)
        missing = [name for name in ("initial_access", "execution", "command_and_control", "lateral_movement", "privilege_escalation", "collection", "exfiltration") if name not in covered]
        uncertainties = ["尚缺少可验证的 %s 阶段。" % stage for stage in missing]
        return AttackChain(
            chain_id=chain_id, run_id=run_id, title="真实多源行为关联攻击链", status="candidate",
            start_time=min(step.start_time for step in steps), end_time=max(step.end_time for step in steps),
            entry_point=ChainStepRef(step_id=steps[0].step_id, stage=steps[0].stage), steps=steps,
            entity_ids=all_entities, detection_ids=[item.detection_id for item in eligible], technique_ids=techniques,
            score=round(mean_score, 3), completeness=round(len(covered & expected) / len(expected), 3),
            uncertainties=uncertainties, evidence_ids=all_evidence, algorithm_version=self.version,
        )

    @staticmethod
    def _stage_representative_key(detection: DetectionResult) -> tuple:
        mapping = DeterministicChainBuilder._mapping(detection)
        if not mapping:
            return (0, 0.0, 0, 0.0)
        return (
            SEVERITY_ORDER[detection.severity],
            round(detection.confidence * mapping.confidence, 6),
            len(detection.evidence_ids),
            -detection.created_at.timestamp(),
        )

    @staticmethod
    def _predecessor_relation(previous: ChainStep, detection: DetectionResult, shared: List[str]) -> str:
        if set(previous.session_ids) & set(detection.session_ids):
            return "same_session"
        if any(item.startswith("file_") for item in shared):
            return "file_lineage"
        if any(item.startswith("user_") for item in shared) and detection.rule_id in {"det.host.privilege_escalation", "det.auth.lateral_movement"}:
            return "identity_change"
        if detection.rule_id.startswith("det.auth."):
            return "authentication_relation"
        if detection.rule_id.startswith("det.network."):
            return "network_relation" if shared else "temporal_relation"
        if shared:
            return "shared_entity_relation"
        return "temporal_relation"

    @staticmethod
    def _mapping(detection: DetectionResult) -> AttackMapping | None:
        if detection.attack_mappings:
            return detection.attack_mappings[0]
        return INFERRED_MAPPINGS.get(detection.rule_id)
