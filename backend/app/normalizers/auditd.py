import binascii
import re
import shlex
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from app.contracts import NetworkContext, RawEventEnvelope, TimeContext, UnifiedSecurityEvent
from app.contracts.common import NetworkEndpoint, SourceKind
from app.contracts.events import ActorContext, ObjectContext
from app.core.ids import stable_id
from app.core.time import parse_timestamp

from .base import AdapterError
from .helpers import file_ref, host_ref, ip_ref, process_ref, provenance, user_ref


AUDIT_RE = re.compile(r"type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)")


def _fields(body: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    try:
        tokens = shlex.split(body, posix=True)
    except ValueError:
        tokens = body.split()
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value.strip('"')
    return result


def _decode_proctitle(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return binascii.unhexlify(value).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except (binascii.Error, ValueError):
        return value


def parse_audit_groups(payload: str) -> List[Dict[str, Any]]:
    groups: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for line in payload.splitlines():
        match = AUDIT_RE.search(line.strip())
        if not match:
            continue
        key = "%s:%s" % (match.group("timestamp"), match.group("serial"))
        group = groups.setdefault(key, {"audit_id": key, "timestamp": match.group("timestamp"), "serial": match.group("serial"), "records": {}})
        record_type = match.group("type")
        group["records"].setdefault(record_type, []).append(_fields(match.group("body")))
    return list(groups.values())


class AuditdAdapter:
    name = "auditd"
    version = "1.1.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == SourceKind.auditd

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        if not isinstance(raw.payload, str):
            raise AdapterError("Auditd adapter expects text records")
        groups = parse_audit_groups(raw.payload)
        if not groups:
            raise AdapterError("Auditd payload contains no audit(timestamp:serial) records")
        return [self._normalize_group(raw, group, index) for index, group in enumerate(groups)]

    def _normalize_group(self, raw: RawEventEnvelope, group: Dict[str, Any], index: int) -> UnifiedSecurityEvent:
        records = group["records"]
        syscall = (records.get("SYSCALL") or records.get("ANOM_ABEND") or [{}])[0]
        execve = (records.get("EXECVE") or [{}])[0]
        cwd = (records.get("CWD") or [{}])[0].get("cwd")
        paths = records.get("PATH") or []
        sockaddr = (records.get("SOCKADDR") or [{}])[0]
        title_record = (records.get("PROCTITLE") or [{}])[0]
        event_time = parse_timestamp(float(group["timestamp"]))
        host = host_ref(raw.source.host_hint, raw.source.sensor_id)
        command_args = [execve[key] for key in sorted(execve) if re.fullmatch(r"a\d+", key)]
        command = " ".join(command_args) or _decode_proctitle(title_record.get("proctitle")) or syscall.get("comm") or syscall.get("exe")
        process_epoch = raw.labels.get("boot_id") or syscall.get("ses") or "audit-unknown-start"
        process = process_ref(host.entity_id, None, syscall.get("pid"), syscall.get("exe") or syscall.get("comm"), process_epoch)
        parent = process_ref(host.entity_id, None, syscall.get("ppid"), None, process_epoch)
        user = user_ref(syscall.get("acct") or syscall.get("uid"), host.entity_id)
        syscall_name = str(syscall.get("syscall") or "").lower()
        name_map = {"59": "execve", "257": "openat", "87": "unlink", "263": "unlinkat", "82": "rename", "90": "chmod", "105": "setuid", "106": "setgid", "42": "connect"}
        syscall_name = name_map.get(syscall_name, syscall_name)
        path = paths[0].get("name") if paths else None
        action, object_type, object_ref = "process.start", "process", process
        if syscall_name in {"open", "openat", "creat"}:
            flags = str(syscall.get("a1") or syscall.get("flags") or "").lower()
            path_types = {str(item.get("nametype") or "").upper() for item in paths}
            action = "file.create" if "CREATE" in path_types or syscall_name == "creat" else "file.modify" if any(token in flags for token in ("wronly", "rdwr", "creat", "trunc")) else "file.read"
            object_type, object_ref = "file", file_ref(host.entity_id, path)
        if syscall_name in {"unlink", "unlinkat"}:
            action, object_type, object_ref = "file.delete", "file", file_ref(host.entity_id, path)
        elif syscall_name in {"setuid", "setgid", "setresuid", "setresgid"} or (syscall.get("uid") and syscall.get("euid") and syscall.get("uid") != syscall.get("euid")):
            action, object_type, object_ref = "privilege.change", "user", user
        elif syscall_name in {"rename", "renameat", "chmod", "fchmod", "chown", "fchown"}:
            action, object_type, object_ref = "file.modify", "file", file_ref(host.entity_id, path)
        if records.get("ANOM_ABEND"):
            action, object_type, object_ref = "process.stop", "process", process
        network = None
        if sockaddr and (sockaddr.get("addr") or sockaddr.get("saddr")):
            dst_ip = sockaddr.get("addr") or sockaddr.get("saddr")
            try:
                destination = ip_ref(dst_ip)
                network = NetworkContext(direction="outbound", transport=(sockaddr.get("protocol") or "tcp").lower(), src=NetworkEndpoint(host_id=host.entity_id), dst=NetworkEndpoint(ip=dst_ip, port=int(sockaddr["port"]) if sockaddr.get("port") else None))
                action, object_type, object_ref = "network.connect", "network", destination
            except ValueError:
                pass
        success = str(syscall.get("success", "yes")).lower() in {"yes", "1", "true"}
        return UnifiedSecurityEvent(
            event_id=stable_id("evt", raw.source.kind.value, raw.source.sensor_id, group["audit_id"], raw.raw_id),
            event_time=event_time, observed_time=raw.observed_time, ingested_time=raw.ingested_time,
            time=TimeContext(original=group["timestamp"], uncertainty_ms=1, quality="synced"), source=raw.source, host=host,
            actor=ActorContext(user=user, process=process, parent_process=parent), object=ObjectContext(type=object_type, ref=object_ref), network=network,
            action=action, event_type="auditd.compound", outcome="success" if success else "failure", severity="informational",
            message=command or "%s audit event" % syscall_name, tags=["linux", "auditd", "compound"],
            extensions={"auditd": {"audit_id": group["audit_id"], "syscall": syscall, "execve": execve, "cwd": cwd, "paths": paths, "proctitle": _decode_proctitle(title_record.get("proctitle")), "sockaddr": sockaddr}},
            provenance=provenance(raw, self.name, self.version),
        )
