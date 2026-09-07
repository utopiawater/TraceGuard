from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from .base import ContractModel


class GraphEntity(ContractModel):
    schema_version: str = "1.0"
    entity_id: str
    entity_type: Literal["host", "user", "process", "file", "registry", "ip", "domain", "session", "alert", "technique", "c2", "evidence"]
    labels: List[str] = Field(default_factory=list)
    display_name: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    identity_quality: Literal["exact", "derived", "provisional"] = "provisional"
    evidence_ids: List[str] = Field(default_factory=list)


class GraphRelation(ContractModel):
    schema_version: str = "1.0"
    relation_id: str
    relation_type: str
    source_entity_id: str
    target_entity_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1)
    derived: bool = False
    event_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)

