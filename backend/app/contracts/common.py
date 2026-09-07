from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import Field

from .base import ContractModel


class SourceKind(str, Enum):
    wazuh = "wazuh"
    sysmon = "sysmon"
    windows_security = "windows_security"
    auditd = "auditd"
    zeek = "zeek"
    dataset = "dataset"
    firewall = "firewall"
    application = "application"


class SourceDescriptor(ContractModel):
    kind: SourceKind
    product: str
    dataset: Optional[str] = None
    sensor_id: str
    host_hint: Optional[str] = None
    source_record_id: Optional[str] = None


class TimeContext(ContractModel):
    original: Optional[Union[str, float, int]] = None
    clock_offset_ms: Optional[float] = None
    uncertainty_ms: float = Field(default=0, ge=0)
    quality: Literal["synced", "estimated", "unsynced", "unknown"] = "unknown"


class EntityRef(ContractModel):
    entity_type: Literal["host", "user", "process", "file", "registry", "ip", "domain", "session", "c2"]
    entity_id: str
    source_ids: List[str] = Field(default_factory=list)
    display_name: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    identity_quality: Literal["exact", "derived", "provisional"] = "provisional"


class NetworkEndpoint(ContractModel):
    ip: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    host_id: Optional[str] = None


class NetworkContext(ContractModel):
    session_id: Optional[str] = None
    direction: Literal["inbound", "outbound", "lateral", "unknown"] = "unknown"
    transport: Optional[Literal["tcp", "udp", "icmp", "other"]] = None
    application: Optional[Literal["dns", "http", "https", "ssh", "smb", "rdp", "smtp", "other"]] = None
    src: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    dst: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    bytes_sent: Optional[int] = Field(default=None, ge=0)
    bytes_received: Optional[int] = Field(default=None, ge=0)
    packets_sent: Optional[int] = Field(default=None, ge=0)
    packets_received: Optional[int] = Field(default=None, ge=0)
    duration_ms: Optional[float] = Field(default=None, ge=0)
    zeek_uid: Optional[str] = None
    dns: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    icmp: Optional[Dict[str, Any]] = None

