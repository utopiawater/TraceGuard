from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from .base import ContractModel


class AttackMapping(ContractModel):
    technique_id: str
    subtechnique_id: Optional[str] = None
    tactic_ids: List[str]
    mapping_rule_id: str
    attack_version: str
    confidence: float = Field(ge=0, le=1)


class Evidence(ContractModel):
    schema_version: str = "1.0"
    evidence_id: str
    kind: Literal["raw_event", "normalized_event", "graph_fact", "intel_fact", "analytic"]
    source_ref: str
    event_ids: List[str] = Field(default_factory=list)
    entity_ids: List[str] = Field(default_factory=list)
    excerpt: Optional[Any] = None
    observed_at: Optional[datetime] = None
    collected_at: datetime
    producer: str
    producer_version: str
    integrity_sha256: Optional[str] = None
    reliability: Literal["direct", "corroborated", "derived", "external_unverified"]
    supports: List[str] = Field(default_factory=list)
    contradicts: List[str] = Field(default_factory=list)


class DetectionResult(ContractModel):
    schema_version: str = "1.0"
    detection_id: str
    run_id: str
    rule_id: str
    rule_version: str
    title: str
    detector_type: Literal["rule", "threshold", "statistical", "correlation"]
    status: Literal["open", "suppressed", "confirmed", "false_positive"] = "open"
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    event_ids: List[str]
    entity_ids: List[str] = Field(default_factory=list)
    session_ids: List[str] = Field(default_factory=list)
    feature_values: Dict[str, Any] = Field(default_factory=dict)
    reason: str
    attack_mappings: List[AttackMapping] = Field(default_factory=list)
    evidence_ids: List[str]
    created_at: datetime


class Note(ContractModel):
    author: str
    text: str
    created_at: datetime


class Alert(ContractModel):
    alert_id: str
    detection_id: str
    case_id: Optional[str] = None
    status: Literal["open", "acknowledged", "investigating", "closed", "suppressed"] = "open"
    assignee: Optional[str] = None
    disposition: Literal["true_positive", "false_positive", "benign_positive", "unknown"] = "unknown"
    analyst_notes: List[Note] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class StepPredecessor(ContractModel):
    step_id: str
    relation: Literal["temporal", "spawn", "same_session", "authentication", "network_flow", "file_lineage", "identity_change", "analyst_link"]
    score: float = Field(ge=0, le=1)
    evidence_ids: List[str] = Field(default_factory=list)


class ChainStep(ContractModel):
    step_id: str
    stage: Literal["initial_access", "execution", "persistence", "privilege_escalation", "credential_access", "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration"]
    tactic_id: str
    technique_id: str
    event_ids: List[str] = Field(default_factory=list)
    detection_ids: List[str] = Field(default_factory=list)
    entity_ids: List[str] = Field(default_factory=list)
    session_ids: List[str] = Field(default_factory=list)
    predecessors: List[StepPredecessor] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime
    score: float = Field(ge=0, le=1)
    evidence_ids: List[str]
    explanation: str


class ChainStepRef(ContractModel):
    step_id: str
    stage: str


class AttackChain(ContractModel):
    schema_version: str = "1.0"
    chain_id: str
    run_id: str
    title: str
    status: Literal["candidate", "confirmed", "dismissed"] = "candidate"
    start_time: datetime
    end_time: datetime
    entry_point: Optional[ChainStepRef] = None
    steps: List[ChainStep]
    entity_ids: List[str] = Field(default_factory=list)
    detection_ids: List[str] = Field(default_factory=list)
    technique_ids: List[str] = Field(default_factory=list)
    score: float = Field(ge=0, le=1)
    completeness: float = Field(ge=0, le=1)
    uncertainties: List[str] = Field(default_factory=list)
    evidence_ids: List[str]
    algorithm_version: str

