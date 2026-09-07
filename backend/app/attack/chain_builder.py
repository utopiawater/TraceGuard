from typing import Dict, List

from app.contracts import AttackChain, ChainStep, DetectionResult
from app.contracts.analytics import ChainStepRef, StepPredecessor
from app.core.ids import stable_id
from app.correlation import CorrelationEngine


TACTIC_STAGE = {"TA0001": "initial_access", "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege_escalation", "TA0006": "credential_access", "TA0007": "discovery", "TA0008": "lateral_movement", "TA0009": "collection", "TA0011": "command_and_control", "TA0010": "exfiltration"}
MAINLINE = {"initial_access", "execution", "command_and_control", "lateral_movement", "privilege_escalation", "collection", "exfiltration"}


class DeterministicChainBuilder:
    version = "1.1.0"

    def __init__(self, correlation=None):
        self.correlation = correlation or CorrelationEngine()

    def build(self, run_id: str, detections: List[DetectionResult]) -> List[AttackChain]:
        groups = self.correlation.groups(detections)
        return [self._build_group(run_id, group) for group in groups if any(TACTIC_STAGE.get(item.attack_mappings[0].tactic_ids[0]) in MAINLINE for item in group)]

    def _build_group(self, run_id: str, eligible: List[DetectionResult]) -> AttackChain:
        severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        eligible.sort(key=lambda item: (item.created_at, severity_order[item.severity], item.detection_id))
        selected = []
        seen_stages = set()
        for detection in eligible:
            tactic = detection.attack_mappings[0].tactic_ids[0]
            stage = TACTIC_STAGE.get(tactic, "execution")
            if stage in MAINLINE and stage not in seen_stages:
                selected.append(detection)
                seen_stages.add(stage)
        eligible = selected
        steps: List[ChainStep] = []
        for index, detection in enumerate(eligible):
            mapping = detection.attack_mappings[0]
            tactic_id = mapping.tactic_ids[0]
            technique_id = mapping.subtechnique_id or mapping.technique_id
            step_id = stable_id("step", detection.detection_id, technique_id)
            predecessors = []
            if steps:
                shared = sorted(set(steps[-1].entity_ids).intersection(detection.entity_ids))
                previous_stage = steps[-1].stage
                current_stage = TACTIC_STAGE.get(tactic_id, "execution")
                relation_by_pair = {
                    ("initial_access", "execution"): "authentication",
                    ("execution", "command_and_control"): "network_flow",
                    ("command_and_control", "lateral_movement"): "network_flow",
                    ("lateral_movement", "privilege_escalation"): "identity_change",
                    ("privilege_escalation", "collection"): "file_lineage",
                    ("collection", "exfiltration"): "file_lineage",
                }
                predecessors = [StepPredecessor(
                    step_id=steps[-1].step_id,
                    relation=relation_by_pair.get((previous_stage, current_stage), "same_session" if set(steps[-1].session_ids) & set(detection.session_ids) else "temporal"),
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
