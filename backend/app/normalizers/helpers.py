import ipaddress
import ntpath
import posixpath
from typing import Any, Dict, Optional

from app.contracts import EntityRef, RawEventEnvelope
from app.contracts.events import EventProvenance
from app.core.ids import stable_id


def host_ref(hostname: Optional[str], sensor_id: str) -> EntityRef:
    name = (hostname or sensor_id).strip().lower()
    return EntityRef(entity_type="host", entity_id=stable_id("host", name), source_ids=[sensor_id], display_name=name, attributes={"hostname": name}, identity_quality="derived")


def user_ref(name: Optional[str], host_id: str, sid: Optional[str] = None) -> Optional[EntityRef]:
    if not name and not sid:
        return None
    identity = sid or "%s|%s" % (host_id, (name or "unknown").lower())
    return EntityRef(entity_type="user", entity_id=stable_id("user", identity), source_ids=[sid] if sid else [], display_name=name, attributes={"sid": sid} if sid else {}, identity_quality="exact" if sid else "derived")


def process_ref(host_id: str, guid: Optional[str], pid: Optional[str], image: Optional[str], start: Any) -> Optional[EntityRef]:
    if not guid and not pid and not image:
        return None
    identity = guid or "%s|%s|%s" % (pid, start, image)
    return EntityRef(entity_type="process", entity_id=stable_id("proc", host_id, identity), source_ids=[guid] if guid else [], display_name=image, attributes={"process_guid": guid, "pid": pid, "image": image}, identity_quality="exact" if guid else "provisional")


def ip_ref(address: str) -> EntityRef:
    normalized = str(ipaddress.ip_address(address))
    return EntityRef(entity_type="ip", entity_id=stable_id("ip", normalized), display_name=normalized, attributes={"address": normalized, "version": ipaddress.ip_address(normalized).version}, identity_quality="exact")


def file_ref(host_id: str, path: Optional[str]) -> Optional[EntityRef]:
    if not path:
        return None
    normalized = ntpath.normpath(path) if "\\" in path or ":" in path else posixpath.normpath(path)
    return EntityRef(entity_type="file", entity_id=stable_id("file", host_id, normalized.lower()), display_name=normalized, attributes={"path": path, "normalized_path": normalized}, identity_quality="derived")


def registry_ref(host_id: str, path: Optional[str]) -> Optional[EntityRef]:
    if not path:
        return None
    normalized = path.replace("/", "\\").strip()
    return EntityRef(entity_type="registry", entity_id=stable_id("registry", host_id, normalized.lower()), display_name=normalized, attributes={"path": path, "normalized_path": normalized}, identity_quality="derived")


def domain_ref(name: Optional[str]) -> Optional[EntityRef]:
    if not name:
        return None
    normalized = name.rstrip(".").lower()
    return EntityRef(entity_type="domain", entity_id=stable_id("domain", normalized), display_name=normalized, attributes={"name": normalized}, identity_quality="exact")


def provenance(raw: RawEventEnvelope, parser: str, version: str, warnings: Optional[list] = None) -> EventProvenance:
    return EventProvenance(raw_id=raw.raw_id, raw_ref=raw.raw_ref, raw_sha256=raw.raw_sha256, parser_name=parser, parser_version=version, mapping_warnings=warnings or [])
