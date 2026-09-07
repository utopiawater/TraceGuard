from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import Field

from .base import ContractModel
from .common import EntityRef, NetworkContext, SourceDescriptor, TimeContext


class RawEventEnvelope(ContractModel):
    schema_version: str = "1.0"
    raw_id: str
    source: SourceDescriptor
    source_record_id: Optional[str] = None
    event_time_raw: Optional[Union[str, float, int]] = None
    observed_time: datetime
    ingested_time: datetime
    payload_format: Literal["json", "text", "xml", "csv", "pcap_ref"]
    payload: Optional[Union[Dict[str, Any], str]] = None
    raw_ref: str
    raw_sha256: str
    labels: Dict[str, Any] = Field(default_factory=dict)


class ActorContext(ContractModel):
    user: Optional[EntityRef] = None
    process: Optional[EntityRef] = None
    parent_process: Optional[EntityRef] = None


class ObjectContext(ContractModel):
    type: Optional[Literal["process", "file", "registry", "user", "host", "network", "memory", "service", "other"]] = None
    ref: Optional[EntityRef] = None


class EventProvenance(ContractModel):
    raw_id: str
    raw_ref: str
    raw_sha256: str
    parser_name: str
    parser_version: str
    mapping_warnings: List[str] = Field(default_factory=list)


class UnifiedSecurityEvent(ContractModel):
    schema_version: str = "1.0"
    event_id: str
    event_time: datetime
    observed_time: datetime
    ingested_time: datetime
    time: TimeContext
    source: SourceDescriptor
    host: Optional[EntityRef] = None
    actor: ActorContext = Field(default_factory=ActorContext)
    object: ObjectContext = Field(default_factory=ObjectContext)
    network: Optional[NetworkContext] = None
    action: str
    event_type: str
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    severity: Literal["informational", "low", "medium", "high", "critical", "unknown"] = "unknown"
    message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extensions: Dict[str, Any] = Field(default_factory=dict)
    provenance: EventProvenance


class Session(ContractModel):
    session_id: str
    session_type: Literal["login", "network"]
    start_time: datetime
    end_time: Optional[datetime] = None
    state: Literal["active", "closed", "timed_out", "orphan_start", "orphan_end"]
    host_id: Optional[str] = None
    user_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_event_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)

