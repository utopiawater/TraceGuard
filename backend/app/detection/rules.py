import ipaddress
import json
import math
import ntpath
import os
import posixpath
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path
from collections import Counter, defaultdict
from fnmatch import fnmatch
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.contracts import AttackMapping, DetectionResult, Evidence, Session, UnifiedSecurityEvent
from app.core.ids import stable_id


def _evidence_for(event_ids: List[str], evidence: List[Evidence]) -> List[str]:
    wanted = set(event_ids)
    return sorted({item.evidence_id for item in evidence if wanted.intersection(item.event_ids)})


def _command_line(event: UnifiedSecurityEvent) -> str:
    sysmon_command = event.extensions.get("sysmon", {}).get("CommandLine")
    audit_execve = event.extensions.get("auditd", {}).get("execve", {})
    audit_args = [audit_execve[key] for key in sorted(audit_execve) if key.startswith("a") and key[1:].isdigit()]
    return str(sysmon_command or " ".join(audit_args) or event.message or "")


SERVICE_PROCESS_NAMES = ("nginx", "httpd", "apache", "apache2", "w3wp", "iisexpress")
SHELL_PROCESS_NAMES = ("sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "cmd.exe", "powershell", "pwsh")
SCRIPT_INTERPRETERS = ("python", "perl", "ruby", "php", "node", "osascript", "wscript", "cscript")
ARCHIVE_TOOLS = ("tar", "zip", "gzip", "7z", "rar", "xz", "bzip2")
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "c:/windows/temp/", "c:/users/public/", "c:/temp/")


def _host_id(event: UnifiedSecurityEvent) -> str:
    return event.host.entity_id if event.host else ""


def _process_id(event: UnifiedSecurityEvent) -> str:
    return event.actor.process.entity_id if event.actor and event.actor.process else ""


def _parent_id(event: UnifiedSecurityEvent) -> str:
    return event.actor.parent_process.entity_id if event.actor and event.actor.parent_process else ""


def _process_name(event: UnifiedSecurityEvent) -> str:
    ref = event.actor.process if event.actor else None
    return str((ref.display_name if ref else None) or (ref.attributes.get("image") if ref else None) or "").lower()


def _parent_name(event: UnifiedSecurityEvent) -> str:
    ref = event.actor.parent_process if event.actor else None
    return str((ref.display_name if ref else None) or (ref.attributes.get("image") if ref else None) or "").lower()


def _dataset_value(event: UnifiedSecurityEvent, key: str) -> Optional[Any]:
    return event.extensions.get("dataset", {}).get(key)


def _path(event: UnifiedSecurityEvent) -> str:
    object_is_path = event.object.type in {"file", "registry"} if event.object else False
    values = [
        event.object.ref.attributes.get("normalized_path") if event.object.ref and object_is_path else None,
        _dataset_value(event, "object_path"),
        _dataset_value(event, "object2_path"),
        event.object.ref.display_name if event.object.ref and object_is_path else None,
        event.actor.process.attributes.get("image") if event.actor.process else None,
        event.actor.process.display_name if event.actor.process else None,
    ]
    value = str(next((item for item in values if item), "")).replace("\\", "/").lower()
    return posixpath.normpath(value) if value.startswith("/") else value


def _is_temp_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return normalized.startswith(TEMP_PREFIXES) or normalized in {"/tmp", "/var/tmp", "/dev/shm"}


def _basename(value: str) -> str:
    return value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _is_service_name(value: str) -> bool:
    name = _basename(value)
    return any(service == name or service in value for service in SERVICE_PROCESS_NAMES)


def _is_shell_or_interpreter(value: str) -> bool:
    name = _basename(value)
    tokens = SHELL_PROCESS_NAMES + SCRIPT_INTERPRETERS
    return any(name == token or name.startswith(f"{token}.") or f"/{token}" in value for token in tokens)


def _is_archiver(event: UnifiedSecurityEvent) -> bool:
    command = _command_line(event).lower()
    image = _process_name(event)
    name = _basename(image)
    return any(name == tool or name.startswith(f"{tool}.") for tool in ARCHIVE_TOOLS) or any(token in command.split()[:3] for token in ARCHIVE_TOOLS)


def _event_ids(items: Iterable[UnifiedSecurityEvent], limit: int = 80) -> List[str]:
    seen = []
    for item in sorted(items, key=lambda event: (event.event_time, event.event_id)):
        if item.event_id not in seen:
            seen.append(item.event_id)
        if len(seen) >= limit:
            break
    return seen


def _entity_ids(items: Iterable[UnifiedSecurityEvent]) -> List[str]:
    values = set()
    for item in items:
        for ref in (item.host, item.actor.user, item.actor.process, item.actor.parent_process, item.object.ref):
            if ref:
                values.add(ref.entity_id)
    return sorted(values)


def _session_ids(items: Iterable[UnifiedSecurityEvent]) -> List[str]:
    return sorted({item.network.session_id for item in items if item.network and item.network.session_id})


def _detection(
    run_id: str,
    rule_id: str,
    version: str,
    title: str,
    detector_type: str,
    severity: str,
    confidence: float,
    items: List[UnifiedSecurityEvent],
    evidence: List[Evidence],
    feature_values: Dict[str, Any],
    reason: str,
    identity: Any,
) -> DetectionResult:
    ids = _event_ids(items)
    return DetectionResult(
        detection_id=stable_id("det", rule_id, version, identity, ids),
        run_id=run_id,
        rule_id=rule_id,
        rule_version=version,
        title=title,
        detector_type=detector_type,
        severity=severity,
        confidence=confidence,
        event_ids=ids,
        entity_ids=_entity_ids(items),
        session_ids=_session_ids(items),
        feature_values=feature_values,
        reason=reason,
        attack_mappings=[],
        evidence_ids=_evidence_for(ids, evidence),
        created_at=max(item.event_time for item in items),
    )


def _within(later: UnifiedSecurityEvent, earlier: UnifiedSecurityEvent, seconds: int) -> bool:
    return 0 <= (later.event_time - earlier.event_time).total_seconds() <= seconds


def _process_related(left: UnifiedSecurityEvent, right: UnifiedSecurityEvent) -> bool:
    left_ids = {_process_id(left), _parent_id(left)} - {""}
    right_ids = {_process_id(right), _parent_id(right)} - {""}
    return bool(left_ids & right_ids)


def _remote_peer(event: UnifiedSecurityEvent) -> Optional[Tuple[str, Optional[int]]]:
    if not event.network:
        return None
    host = _host_id(event)
    endpoints = [event.network.src, event.network.dst]
    for endpoint in endpoints:
        if endpoint.host_id and endpoint.host_id == host:
            continue
        if endpoint.ip:
            return (endpoint.ip, endpoint.port)
    dst = event.network.dst
    src = event.network.src
    if event.network.direction in {"outbound", "unknown"} and dst.ip:
        return (dst.ip, dst.port)
    if src.ip:
        return (src.ip, src.port)
    return None


def _canonical_peer_key(event: UnifiedSecurityEvent) -> Optional[str]:
    peer = _remote_peer(event)
    return "%s:%s" % peer if peer else None


def _is_unexpected_peer(event: UnifiedSecurityEvent) -> bool:
    if not event.network:
        return False
    peer = _remote_peer(event)
    if not peer:
        return False
    local_ip = event.network.src.ip if event.network.direction in {"outbound", "unknown"} else event.network.dst.ip
    return ServiceProcessExternalConnectionRule._is_unexpected_destination(local_ip, peer[0])


def _is_outbound_anchor(event: UnifiedSecurityEvent) -> bool:
    return bool(event.network and event.action in {"network.connect", "network.send"} and event.network.direction in {"outbound", "unknown"} and _is_unexpected_peer(event))


def _network_bytes(event: UnifiedSecurityEvent) -> int:
    if not event.network:
        return 0
    return int(event.network.bytes_sent or 0) + int(event.network.bytes_received or 0)


def _asset_hint_entity_ids(uri: str) -> List[str]:
    hints = []
    try:
        query = urlsplit(uri).query
    except ValueError:
        query = ""
    for key, value in parse_qsl(query, keep_blank_values=False):
        if key.lower() in {"host", "hostname", "asset", "node"} and value.strip():
            hints.append(value.strip().lower())
    return sorted({stable_id("host", hint) for hint in hints})


class SuspiciousPowerShellRule:
    rule_id = "det.host.suspicious_powershell"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        results = []
        for event in events:
            if event.action != "process.start" or not event.actor.process:
                continue
            image = str(event.actor.process.attributes.get("image") or "").lower()
            command = str(event.extensions.get("sysmon", {}).get("CommandLine") or "").lower()
            indicators = [token for token in ("-enc", "-encodedcommand", "invoke-webrequest", "downloadstring") if token in command]
            if "powershell" not in image or not indicators:
                continue
            entity_ids = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.actor.parent_process) if ref]
            evidence_ids = _evidence_for([event.event_id], evidence)
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id), run_id=run_id,
                rule_id=self.rule_id, rule_version=self.version, title="可疑 PowerShell 命令执行", detector_type="rule",
                severity="high", confidence=0.92, event_ids=[event.event_id], entity_ids=entity_ids,
                feature_values={"matched_tokens": indicators, "image": image},
                reason="PowerShell 进程命令行包含高风险编码或下载语义。",
                attack_mappings=[], evidence_ids=evidence_ids, created_at=event.event_time,
            ))
        return results


class RemoteInteractiveLogonRule:
    rule_id = "det.auth.remote_interactive_logon"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        results = []
        for event in events:
            fields = event.extensions.get("windows_security", {})
            if event.action != "auth.logon" or event.outcome != "success" or str(fields.get("LogonType")) not in {"3", "10"}:
                continue
            evidence_ids = _evidence_for([event.event_id], evidence)
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.object.ref) if ref]
            logon_type = str(fields.get("LogonType"))
            title = "Windows 网络登录" if logon_type == "3" else "Windows 远程交互式登录"
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id), run_id=run_id,
                rule_id=self.rule_id, rule_version=self.version, title=title, detector_type="rule",
                severity="medium", confidence=0.78, event_ids=[event.event_id], entity_ids=refs,
                session_ids=[event.object.ref.entity_id] if event.object.ref else [],
                feature_values={"logon_type": fields.get("LogonType"), "logon_semantics": "network" if logon_type == "3" else "remote_interactive", "source_ip": fields.get("IpAddress")},
                reason="Windows Security 记录到成功的远程或网络登录，需要结合后续进程活动复核。",
                attack_mappings=[], evidence_ids=evidence_ids, created_at=event.event_time,
            ))
        return results


class CrossSourceNetworkRule:
    rule_id = "det.network.cross_source_interpreter_connection"
    version = "1.0.0"

    def evaluate(self, run_id: str, events: List[UnifiedSecurityEvent], sessions: List[Session], evidence: List[Evidence]) -> List[DetectionResult]:
        host_events = [event for event in events if event.action == "network.connect" and event.network and event.actor.process]
        network_events = [event for event in events if event.action == "network.flow" and event.network]
        results = []
        for host_event in host_events:
            image = str(host_event.actor.process.attributes.get("image") or "").lower()
            if not any(name in image for name in ("powershell", "pwsh", "cmd.exe", "wscript", "cscript")):
                continue
            for network_event in network_events:
                h, n = host_event.network, network_event.network
                tuple_match = (h.src.ip, h.src.port, h.dst.ip, h.dst.port, h.transport) == (n.src.ip, n.src.port, n.dst.ip, n.dst.port, n.transport)
                delta = abs((host_event.event_time - network_event.event_time).total_seconds())
                if not tuple_match or delta > 2.0:
                    continue
                event_ids = [host_event.event_id, network_event.event_id]
                evidence_ids = _evidence_for(event_ids, evidence)
                entity_ids = sorted({ref.entity_id for ref in (host_event.host, host_event.actor.process, host_event.object.ref, network_event.object.ref) if ref})
                session_ids = sorted({item for item in (h.session_id, n.session_id) if item})
                results.append(DetectionResult(
                    detection_id=stable_id("det", self.rule_id, self.version, event_ids), run_id=run_id,
                    rule_id=self.rule_id, rule_version=self.version, title="脚本解释器连接获得端网双源印证", detector_type="correlation",
                    severity="high", confidence=0.9, event_ids=event_ids, entity_ids=entity_ids, session_ids=session_ids,
                    feature_values={"tuple_match": True, "time_delta_ms": round(delta * 1000, 3), "independent_sources": ["sysmon", "zeek"]},
                    reason="Sysmon 进程网络连接与 Zeek 会话的五元组和时间窗口一致。",
                    attack_mappings=[], evidence_ids=evidence_ids, created_at=max(host_event.event_time, network_event.event_time),
                ))
        return results


class LateralMovementRule:
    rule_id = "det.auth.lateral_movement"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        logons = [event for event in events if event.action == "auth.logon" and event.outcome == "success" and str(event.extensions.get("windows_security", {}).get("LogonType")) in {"3", "10"}]
        flows = [event for event in events if event.network and event.action in {"network.flow", "network.connect"}]
        for logon in logons:
            source_ip = logon.extensions.get("windows_security", {}).get("IpAddress")
            for flow in flows:
                delta = abs((logon.event_time - flow.event_time).total_seconds())
                service_port = flow.network.dst.port
                if delta > 30 or source_ip not in {flow.network.src.ip, flow.network.dst.ip} or service_port not in {22, 445, 3389, 5985, 5986}:
                    continue
                event_ids = [logon.event_id, flow.event_id]
                refs = sorted({ref.entity_id for ref in (logon.host, logon.actor.user, logon.object.ref, flow.host, flow.object.ref) if ref})
                results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event_ids), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="登录与远程服务连接关联", detector_type="correlation", severity="high", confidence=0.86, event_ids=event_ids, entity_ids=refs, session_ids=sorted({value for value in (logon.object.ref.entity_id if logon.object.ref else None, flow.network.session_id) if value}), feature_values={"source_ip": source_ip, "service_port": service_port, "time_delta_seconds": round(delta, 3)}, reason="远程服务网络连接与目标主机成功登录在时间和源地址上相符。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=max(logon.event_time, flow.event_time)))
        return results


class PrivilegeEscalationRule:
    rule_id = "det.host.privilege_escalation"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action not in {"auth.privilege_assigned", "privilege.change"}:
                continue
            fields = event.extensions.get("windows_security", {}) or event.extensions.get("auditd", {}).get("syscall", {})
            if event.action == "privilege.change" and fields.get("uid") == fields.get("euid"):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="权限提升或高权限令牌分配", detector_type="rule", severity="high", confidence=0.9, event_ids=event_ids, entity_ids=sorted(set(refs)), feature_values={"action": event.action, "privileges": fields.get("PrivilegeList"), "uid": fields.get("uid"), "euid": fields.get("euid")}, reason="操作系统审计记录证明账户获得高权限令牌或有效身份发生提升。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results


class SensitiveFileCollectionRule:
    rule_id = "det.host.sensitive_file_collection"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            path = str((event.object.ref.attributes.get("normalized_path") if event.object.ref else "") or "").lower()
            if event.action != "file.read" or not self._matches_sensitive_path(path):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="敏感文件访问与收集", detector_type="rule", severity="high", confidence=0.88, event_ids=event_ids, entity_ids=refs, feature_values={"path": path, "operation": event.action}, reason="进程读取了凭据或业务敏感路径，可作为后续暂存与外传的数据来源证据。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results

    @classmethod
    def _patterns(cls) -> List[str]:
        configured = os.getenv("TRACEGUARD_SENSITIVE_PATHS", "")
        values = [item.strip().lower() for item in configured.split(";") if item.strip()]
        if values:
            return values
        policy_path = Path(os.getenv("TRACEGUARD_SENSITIVE_PATH_POLICY", Path(__file__).parents[3] / "knowledge" / "policies" / "sensitive_paths.json"))
        try:
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            patterns = payload.get("patterns", []) if isinstance(payload, dict) else []
            return [str(item).lower() for item in patterns if str(item).strip()]
        except (OSError, json.JSONDecodeError):
            return []

    @classmethod
    def _matches_sensitive_path(cls, path: str) -> bool:
        normalized = ntpath.normpath(path) if "\\" in path or ":" in path else posixpath.normpath(path)
        normalized = normalized.replace("\\", "/").lower()
        for pattern in cls._patterns():
            candidate = pattern.replace("\\", "/").lower()
            if fnmatch(normalized, candidate) or fnmatch(path, pattern):
                return True
        return False


class DataExfiltrationRule:
    rule_id = "det.network.data_exfiltration"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        collections = [event for event in events if event.action == "file.read" and event.object.ref]
        transfers = [event for event in events if event.network and (event.action == "network.file_transfer" or (event.action == "network.flow" and (event.network.bytes_sent or 0) >= 50000))]
        results = []
        for transfer in transfers:
            prior = [event for event in collections if 0 <= (transfer.event_time - event.event_time).total_seconds() <= 600 and (not event.host or not transfer.host or event.host.entity_id == transfer.host.entity_id)]
            if not prior:
                continue
            source = prior[-1]
            event_ids = [source.event_id, transfer.event_id]
            refs = sorted({ref.entity_id for event in (source, transfer) for ref in (event.host, event.actor.process, event.object.ref) if ref})
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event_ids), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="敏感数据访问后外传", detector_type="correlation", severity="critical", confidence=0.91, event_ids=event_ids, entity_ids=refs, session_ids=[transfer.network.session_id] if transfer.network.session_id else [], feature_values={"bytes_sent": transfer.network.bytes_sent, "destination": transfer.network.dst.ip, "delay_seconds": round((transfer.event_time-source.event_time).total_seconds(), 3)}, reason="同一主机先访问敏感数据，随后向外部会话发送大量数据，形成文件来源到网络外传的证据链。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=transfer.event_time))
        return results


class ArchiveCollectedDataRule:
    rule_id = "det.host.archive_collected_data"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action != "process.start" or not event.actor.process:
                continue
            command = _command_line(event).lower()
            image = str(event.actor.process.display_name or event.actor.process.attributes.get("image") or "").lower()
            is_archiver = any(name in image for name in ("tar", "zip", "gzip", "7z", "rar")) or any(token in command.split()[:2] for token in ("tar", "zip", "gzip", "7z", "rar"))
            if not is_archiver:
                continue
            if not any(token in command for token in ("/tmp/", "/var/tmp", ".tar", ".tgz", ".gz", ".zip", ".7z", ".rar")):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="收集数据归档候选",
                detector_type="rule",
                severity="medium",
                confidence=0.78,
                event_ids=event_ids,
                entity_ids=sorted(set(refs)),
                feature_values={"command": command, "image": image, "status": "archive_candidate"},
                reason="归档工具将数据写入临时目录或归档文件名，符合收集后打包阶段的候选行为，需要结合前序敏感文件访问确认。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=event.event_time,
            ))
        return results


class SuspiciousHttpClientTransferRule:
    rule_id = "det.host.suspicious_http_client_transfer"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action != "process.start" or not event.actor.process:
                continue
            command = _command_line(event)
            command_lower = command.lower()
            image = str(event.actor.process.display_name or event.actor.process.attributes.get("image") or "").lower()
            if not any(name in image for name in ("curl", "wget", "powershell", "python")) and not any(token in command_lower for token in ("curl http", "wget http", "invoke-webrequest")):
                continue
            if "http://" not in command_lower and "https://" not in command_lower:
                continue
            status = "exfiltration_simulation" if "simulation" in command_lower else "suspected_exfiltration"
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="HTTP 客户端外联传输候选",
                detector_type="rule",
                severity="medium",
                confidence=0.7 if status == "suspected_exfiltration" else 0.64,
                event_ids=event_ids,
                entity_ids=sorted(set(refs)),
                feature_values={"command": command, "image": image, "status": status},
                reason="主机执行 HTTP 客户端访问外部 URL。若只存在 URL 或模拟字段，只能判定为疑似/模拟外传，不能声称数据已确认外传。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=event.event_time,
            ))
        return results


class MemoryTamperingRule:
    rule_id = "det.host.memory_tampering"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action not in {"memory.remote_thread", "memory.process_tamper"}:
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="代表性内存篡改行为", detector_type="rule", severity="high", confidence=0.84, event_ids=event_ids, entity_ids=refs, feature_values={"sysmon_event_id": event.extensions.get("event_id"), "action": event.action}, reason="Sysmon 记录到远程线程、跨进程访问或进程篡改事件。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results


class TempDirectoryExecutionRule:
    rule_id = "det.host.temp_directory_execution"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            path = self._executable_path(event)
            if event.action != "process.start" or not (path.startswith("/tmp/") or path in {"/tmp", "/var/tmp"}):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.actor.parent_process, event.object.ref) if ref]
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="临时目录可执行文件运行",
                detector_type="rule",
                severity="high",
                confidence=0.86,
                event_ids=event_ids,
                entity_ids=sorted(set(refs)),
                feature_values={"path": path, "process": event.actor.process.display_name if event.actor.process else None, "outcome": event.outcome},
                reason="进程尝试从 /tmp 等临时目录执行文件，该位置常用于暂存下载载荷或一次性工具。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=event.event_time,
            ))
        return results

    @staticmethod
    def _executable_path(event) -> str:
        values = [
            event.object.ref.attributes.get("normalized_path") if event.object.ref else None,
            event.actor.process.attributes.get("image") if event.actor.process else None,
            event.actor.process.display_name if event.actor.process else None,
        ]
        return str(next((item for item in values if item), "")).lower().replace("\\", "/")


class ServiceProcessExternalConnectionRule:
    rule_id = "det.network.service_process_external_connection"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        service_names = ("nginx", "httpd", "apache2", "iisexpress", "w3wp")
        results = []
        for event in events:
            if event.action not in {"network.connect", "network.send"} or not event.network or not event.actor.process:
                continue
            image = str(event.actor.process.display_name or event.actor.process.attributes.get("image") or "").lower()
            if not any(name in image for name in service_names):
                continue
            dst_ip = event.network.dst.ip
            if not dst_ip or not self._is_unexpected_destination(event.network.src.ip, dst_ip):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="服务进程异常外部通信",
                detector_type="rule",
                severity="medium",
                confidence=0.74,
                event_ids=event_ids,
                entity_ids=sorted(set(refs)),
                session_ids=[event.network.session_id] if event.network.session_id else [],
                feature_values={"process": image, "destination": dst_ip, "port": event.network.dst.port, "action": event.action},
                reason="面向入站请求的服务进程主动连接或发送数据到公网或跨私网网段目的地，需结合资产角色复核是否为反连、代理或异常上游通信。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=event.event_time,
            ))
        return results

    @staticmethod
    def _is_unexpected_destination(src_ip: str | None, dst_ip: str) -> bool:
        try:
            dst = ipaddress.ip_address(dst_ip)
            if not (dst.is_private or dst.is_loopback or dst.is_link_local or dst.is_multicast or dst.is_reserved):
                return True
            if not src_ip:
                return False
            src = ipaddress.ip_address(src_ip)
            if src.version != dst.version:
                return True
            if src.is_private and dst.is_private:
                return ipaddress.ip_network(f"{src_ip}/24", strict=False) != ipaddress.ip_network(f"{dst_ip}/24", strict=False)
            return False
        except ValueError:
            return False


class NetworkServiceScanningRule:
    rule_id = "det.network.service_scanning"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        by_process = defaultdict(list)
        for event in events:
            if not event.network or not event.actor.process or event.action not in {"network.connect", "network.send", "network.receive", "network.accept"}:
                continue
            key = (event.host.entity_id if event.host else None, event.actor.process.entity_id)
            by_process[key].append(event)
        results = []
        for _, items in by_process.items():
            items.sort(key=lambda item: item.event_time)
            for index, first in enumerate(items):
                window = [item for item in items[index:] if 0 <= (item.event_time - first.event_time).total_seconds() <= 300]
                targets = sorted({(item.network.dst.ip, item.network.dst.port) for item in window if item.network.dst.ip and item.network.dst.port})
                if len(targets) < 4:
                    continue
                selected = window[:20]
                event_ids = [item.event_id for item in selected]
                refs = sorted({ref.entity_id for item in selected for ref in (item.host, item.actor.process, item.object.ref) if ref})
                sessions_ids = sorted({item.network.session_id for item in selected if item.network.session_id})
                results.append(DetectionResult(
                    detection_id=stable_id("det", self.rule_id, self.version, event_ids),
                    run_id=run_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    title="网络服务扫描行为",
                    detector_type="threshold",
                    severity="medium",
                    confidence=0.78,
                    event_ids=event_ids,
                    entity_ids=refs,
                    session_ids=sessions_ids,
                    feature_values={"distinct_targets": len(targets), "sample_targets": ["%s:%s" % target for target in targets[:12]], "window_seconds": 300},
                    reason="同一主机进程在短时间内触达多个不同 IP/端口组合，符合网络服务发现或扫描的统计特征。",
                    attack_mappings=[],
                    evidence_ids=_evidence_for(event_ids, evidence),
                    created_at=max(item.event_time for item in selected),
                ))
                break
        return results


class FlowNetworkServiceScanningRule:
    rule_id = "det.network.flow_service_scanning"
    version = "1.0.0"

    def __init__(self, min_targets: int | None = None, window_seconds: int | None = None) -> None:
        self.min_targets = min_targets or int(os.getenv("TRACEGUARD_SCAN_MIN_TARGETS", "4"))
        self.window_seconds = window_seconds or int(os.getenv("TRACEGUARD_SCAN_WINDOW_SECONDS", "300"))

    def evaluate(self, run_id, events, sessions, evidence):
        by_source = defaultdict(list)
        for event in events:
            if not event.network or event.actor.process or event.action not in {"network.flow", "http.request", "network.connect"}:
                continue
            if not event.network.src.ip or not event.network.dst.ip:
                continue
            by_source[event.network.src.ip].append(event)
        results = []
        for src_ip, items in by_source.items():
            items.sort(key=lambda item: item.event_time)
            for index, first in enumerate(items):
                window = [item for item in items[index:] if 0 <= (item.event_time - first.event_time).total_seconds() <= self.window_seconds]
                targets = {(item.network.dst.ip, item.network.dst.port) for item in window if item.network.dst.ip and item.network.dst.port}
                hosts = {host for host, _ in targets if host}
                ports = {port for _, port in targets if port is not None}
                if len(targets) < self.min_targets:
                    continue
                scan_type = "single_host_multi_port" if len(hosts) == 1 and len(ports) >= self.min_targets else "multi_host"
                selected = window[:25]
                event_ids = [item.event_id for item in selected]
                refs = sorted({ref.entity_id for item in selected for ref in (item.host, item.object.ref) if ref})
                results.append(DetectionResult(
                    detection_id=stable_id("det", self.rule_id, self.version, src_ip, event_ids),
                    run_id=run_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    title="流量侧网络服务扫描",
                    detector_type="threshold",
                    severity="medium",
                    confidence=0.76 if scan_type == "single_host_multi_port" else 0.8,
                    event_ids=event_ids,
                    entity_ids=refs,
                    session_ids=sorted({item.network.session_id for item in selected if item.network.session_id}),
                    feature_values={"source_ip": src_ip, "distinct_targets": len(targets), "distinct_hosts": len(hosts), "distinct_ports": len(ports), "scan_type": scan_type, "window_seconds": self.window_seconds},
                    reason="同一源地址在短时间窗口内触达多个目标 IP/端口，且网络事件不依赖主机进程上下文，符合流量侧服务扫描候选特征。",
                    attack_mappings=[],
                    evidence_ids=_evidence_for(event_ids, evidence),
                    created_at=max(item.event_time for item in selected),
                ))
                break
        return results


class HttpC2CandidateRule:
    rule_id = "det.network.http_c2_candidate"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        groups = defaultdict(list)
        for event in events:
            if event.action != "http.request" or not event.network or not event.network.http:
                continue
            uri = str(event.network.http.get("uri") or "").lower()
            user_agent = str(event.network.http.get("user_agent") or "").lower()
            if not any(token in f"{uri} {user_agent}" for token in ("beacon", "checkin", "callback", "tasking")):
                continue
            key = (event.network.src.ip, event.network.dst.ip or event.source.sensor_id)
            groups[key].append(event)
        results = []
        for key, items in groups.items():
            items.sort(key=lambda item: item.event_time)
            event_ids = [item.event_id for item in items[:20]]
            refs = sorted(
                {ref.entity_id for item in items[:20] for ref in (item.host, item.object.ref) if ref}
                | {entity_id for item in items[:20] for entity_id in _asset_hint_entity_ids(str(item.network.http.get("uri") or ""))}
            )
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, key, event_ids),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="HTTP C2 候选通信",
                detector_type="rule",
                severity="medium",
                confidence=0.72,
                event_ids=event_ids,
                entity_ids=refs,
                session_ids=sorted({item.network.session_id for item in items[:20] if item.network.session_id}),
                feature_values={"peer": key, "request_count": len(items), "uris": [str(item.network.http.get("uri") or "") for item in items[:10]], "status": "suspected_c2"},
                reason="HTTP 请求自身命中信标、回连或任务领取语义，只能说明存在 C2 候选通信，仍需网络流量和主机证据进一步确认。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=max(item.event_time for item in items),
            ))
        return results


class WebProbingRule:
    rule_id = "det.web.probing"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        by_source = defaultdict(list)
        for event in events:
            if event.action != "http.request" or not event.network or not event.network.http:
                continue
            uri = str(event.network.http.get("uri") or "").lower()
            user_agent = str(event.network.http.get("user_agent") or "").lower()
            if any(token in uri for token in ("../", "%2e%2e", "/admin", "/login", "/upload", "/hnap1")) or "nmap" in user_agent:
                by_source[(event.network.src.ip, event.network.dst.host_id or event.network.dst.ip)].append(event)
        results = []
        for key, items in by_source.items():
            if len(items) < 2:
                continue
            items.sort(key=lambda item: item.event_time)
            event_ids = [item.event_id for item in items[:20]]
            refs = sorted({ref.entity_id for item in items[:20] for ref in (item.host, item.object.ref) if ref})
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, key, event_ids),
                run_id=run_id,
                rule_id=self.rule_id,
                rule_version=self.version,
                title="Web 探测与可疑路径访问",
                detector_type="threshold",
                severity="medium",
                confidence=0.77,
                event_ids=event_ids,
                entity_ids=refs,
                session_ids=sorted({item.network.session_id for item in items[:20] if item.network.session_id}),
                feature_values={"source": key[0], "request_count": len(items), "sample_uris": [str(item.network.http.get("uri") or "") for item in items[:10]], "status": "exploitation_candidate"},
                reason="同一来源出现路径遍历、管理入口探测或 Nmap Web 探测请求；这证明 Web 探测候选，不等同于漏洞利用成功。",
                attack_mappings=[],
                evidence_ids=_evidence_for(event_ids, evidence),
                created_at=max(item.event_time for item in items),
            ))
        return results


class TempFileLifecycleRule:
    rule_id = "det.host.temp_file_lifecycle"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        grouped = defaultdict(list)
        for event in events:
            path = _path(event)
            if path and event.action in {"file.open", "file.write", "file.modify", "process.start", "file.delete", "file.create"}:
                grouped[(_host_id(event), path)].append(event)
        results = []
        for (host, path), items in grouped.items():
            if not _is_temp_path(path):
                continue
            items.sort(key=lambda item: item.event_time)
            for index, first in enumerate(items):
                window = [item for item in items[index:] if 0 <= (item.event_time - first.event_time).total_seconds() <= 300]
                has_write = any(item.action in {"file.open", "file.write", "file.create"} for item in window)
                has_chmod = any(item.action == "file.modify" for item in window)
                execs = [item for item in window if item.action == "process.start"]
                deletes = [item for item in window if item.action == "file.delete"]
                if execs and ((has_write and has_chmod) or has_write or deletes):
                    feature = {"host": host, "path": path, "has_write_or_open": has_write, "has_permission_change": has_chmod, "has_execute": True, "has_delete": bool(deletes), "window_seconds": 300}
                    results.append(_detection(run_id, self.rule_id, self.version, "临时文件落地执行生命周期", "correlation", "high", 0.86, window, evidence, feature, "同一主机临时路径在短时间内出现落地、权限变更、执行或清理的连续生命周期，单个文件操作未被单独判定。", (host, path, int(first.event_time.timestamp() // 300))))
                    break
        return results


class PermissionThenExecutionRule:
    rule_id = "det.host.permission_then_execution"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        by_path = defaultdict(list)
        for event in events:
            path = _path(event)
            if path and event.action in {"file.modify", "process.start"}:
                by_path[(_host_id(event), path)].append(event)
        for key, items in by_path.items():
            chmods = [item for item in items if item.action == "file.modify"]
            execs = [item for item in items if item.action == "process.start"]
            for chmod in sorted(chmods, key=lambda item: item.event_time):
                matches = [item for item in execs if _within(item, chmod, 120)]
                if matches:
                    selected = [chmod, matches[0]]
                    path = key[1]
                    results.append(_detection(run_id, self.rule_id, self.version, "权限变更后执行文件", "correlation", "medium", 0.76, selected, evidence, {"path": path, "window_seconds": 120, "temp_path": _is_temp_path(path)}, "同一文件先发生权限修改，随后在有限时间窗内被执行；该规则只在 chmod 与执行可关联时触发。", key))
                    break
        return results


class ExecutionCleanupRule:
    rule_id = "det.host.execution_cleanup"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        by_path = defaultdict(list)
        for event in events:
            path = _path(event)
            if path and _is_temp_path(path) and event.action in {"process.start", "file.delete"}:
                by_path[(_host_id(event), path)].append(event)
        for key, items in by_path.items():
            execs = [item for item in items if item.action == "process.start"]
            deletes = [item for item in items if item.action == "file.delete"]
            for executed in sorted(execs, key=lambda item: item.event_time):
                cleanup = [item for item in deletes if _within(item, executed, 120)]
                if cleanup:
                    selected = [executed, cleanup[0]]
                    results.append(_detection(run_id, self.rule_id, self.version, "临时可执行文件运行后清理", "correlation", "medium", 0.78, selected, evidence, {"path": key[1], "window_seconds": 120}, "临时目录文件执行后很快被删除，符合执行后清理痕迹；普通删除不会单独触发。", key))
                    break
        return results


class ServiceSpawnShellRule:
    rule_id = "det.host.service_spawn_shell"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action != "process.start" or not event.actor.process or not event.actor.parent_process:
                continue
            parent = _parent_name(event)
            child = _process_name(event)
            path = _path(event)
            if not _is_service_name(parent):
                continue
            if "sshd" in parent and _is_shell_or_interpreter(child):
                continue
            if _is_shell_or_interpreter(child) or _is_temp_path(path):
                results.append(_detection(run_id, self.rule_id, self.version, "对外服务进程派生解释器", "correlation", "high", 0.88, [event], evidence, {"parent": parent, "child": child, "path": path}, "Web/IIS 等对外服务进程直接派生 shell、脚本解释器或临时目录可执行文件，父子进程谱系可验证。", (event.event_id, parent, child)))
        return results


class TempExecNetworkRule:
    rule_id = "det.network.temp_exec_network"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        starts = [event for event in events if event.action == "process.start" and _is_temp_path(_path(event)) and _process_id(event)]
        network = [event for event in events if event.network and event.action in {"network.connect", "network.send"} and _process_id(event)]
        for start in starts:
            related = [item for item in network if _process_related(start, item) and _within(item, start, 120) and _is_unexpected_peer(item)]
            if related:
                selected = [start] + related[:20]
                results.append(_detection(run_id, self.rule_id, self.version, "临时可执行文件启动后外联", "correlation", "high", 0.86, selected, evidence, {"path": _path(start), "peers": sorted({_canonical_peer_key(item) for item in related if _canonical_peer_key(item)}), "window_seconds": 120}, "临时目录可执行文件启动后，同进程谱系出现主动跨网段或外部通信，形成执行到 C2 的关联证据。", (_host_id(start), _process_id(start), int(start.event_time.timestamp() // 120))))
        return results


class SuspiciousServiceSessionRule:
    rule_id = "det.network.suspicious_service_session"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        groups = defaultdict(list)
        for event in events:
            if not event.network or not event.actor.process or event.action not in {"network.connect", "network.send", "network.receive"}:
                continue
            if not _is_service_name(_process_name(event)):
                continue
            peer = _canonical_peer_key(event)
            if peer:
                groups[(_host_id(event), _process_id(event), peer)].append(event)
        results = []
        for key, items in groups.items():
            items.sort(key=lambda item: item.event_time)
            anchors = [item for item in items if _is_outbound_anchor(item)]
            if not anchors:
                continue
            for anchor in anchors:
                window = [item for item in items if 0 <= abs((item.event_time - anchor.event_time).total_seconds()) <= 300]
                if (max(item.event_time for item in window) - min(item.event_time for item in window)).total_seconds() < 1:
                    continue
                has_send = any(item.action in {"network.connect", "network.send"} for item in window)
                has_receive = any(item.action == "network.receive" for item in window)
                if has_send and has_receive:
                    results.append(_detection(run_id, self.rule_id, self.version, "服务进程异常双向外联会话", "correlation", "high", 0.86, window[:80], evidence, {"peer": key[2], "event_count": len(window), "bytes": sum(_network_bytes(item) for item in window), "window_seconds": 300}, "对外服务进程先出现主动跨网段/外部连接锚点，并与同一 canonical peer 形成双向通信；普通入站 Web 请求响应不会触发。", key))
                    break
        return results


class AnchoredPeerTrafficRule:
    rule_id = "det.network.anchored_peer_traffic"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        anchors = []
        for event in events:
            if event.action == "process.start" and (_is_temp_path(_path(event)) or (_is_service_name(_parent_name(event)) and _is_shell_or_interpreter(_process_name(event)))):
                anchors.append(event)
            elif event.action.startswith("privilege.") and _process_id(event):
                anchors.append(event)
            elif event.network and _is_service_name(_process_name(event)) and _is_outbound_anchor(event):
                anchors.append(event)
        network = [event for event in events if event.network and event.action in {"network.connect", "network.send", "network.receive"}]
        results = []
        seen = set()
        for anchor in anchors:
            for peer in sorted({_canonical_peer_key(item) for item in network if _canonical_peer_key(item)}):
                related = [item for item in network if _canonical_peer_key(item) == peer and abs((item.event_time - anchor.event_time).total_seconds()) <= 300 and (_process_related(anchor, item) or _host_id(anchor) == _host_id(item))]
                if len(related) < 2 or not any(item.action in {"network.connect", "network.send"} for item in related):
                    continue
                identity = (_host_id(anchor), _process_id(anchor), peer, int(anchor.event_time.timestamp() // 300))
                if identity in seen:
                    continue
                seen.add(identity)
                selected = [anchor] + related[:60]
                results.append(_detection(run_id, self.rule_id, self.version, "高风险进程锚定的 peer 通信", "correlation", "medium", 0.74, selected, evidence, {"anchor_action": anchor.action, "peer": peer, "supporting_network_events": len(related)}, "仅在临时执行、服务派生解释器、服务主动外联或权限变化等高风险锚点之后，聚合同 peer 的收发证据。", identity))
        return results


class BeaconingSessionRule:
    rule_id = "det.network.beaconing_session"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        groups = defaultdict(list)
        for event in events:
            if event.network and event.action in {"network.connect", "network.send"} and _process_id(event) and _is_unexpected_peer(event):
                peer = _canonical_peer_key(event)
                if peer:
                    groups[(_host_id(event), _process_id(event), peer)].append(event)
        results = []
        for key, items in groups.items():
            items.sort(key=lambda item: item.event_time)
            if len(items) < 5:
                continue
            intervals = [(items[index].event_time - items[index - 1].event_time).total_seconds() for index in range(1, len(items))]
            positive = [value for value in intervals if value > 0]
            if len(positive) < 4:
                continue
            avg = sum(positive) / len(positive)
            if avg <= 0:
                continue
            variance = sum((value - avg) ** 2 for value in positive) / len(positive)
            cv = math.sqrt(variance) / avg
            if cv > 0.65:
                continue
            results.append(_detection(run_id, self.rule_id, self.version, "周期性主动通信候选", "statistical", "medium", 0.76, items[:80], evidence, {"peer": key[2], "request_count": len(items), "average_interval": round(avg, 3), "interval_cv": round(cv, 3), "bytes": sum(_network_bytes(item) for item in items)}, "同一主机/进程/peer 存在多次主动通信且间隔较稳定，并先满足外部或跨网段主动通信锚点，形成 C2 beacon 候选。", key))
        return results


class SensitiveReadBurstRule:
    rule_id = "det.host.sensitive_read_burst"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        grouped = defaultdict(list)
        for event in events:
            path = _path(event)
            if event.action == "file.read" and path and SensitiveFileCollectionRule._matches_sensitive_path(path):
                grouped[(_host_id(event), _process_id(event))].append(event)
        results = []
        for key, items in grouped.items():
            items.sort(key=lambda item: item.event_time)
            for index, first in enumerate(items):
                window = [item for item in items[index:] if _within(item, first, 120)]
                paths = sorted({_path(item) for item in window})
                if len(paths) >= 3:
                    results.append(_detection(run_id, self.rule_id, self.version, "敏感路径集中读取", "threshold", "high", 0.84, window[:80], evidence, {"distinct_sensitive_paths": len(paths), "paths": paths[:20], "window_seconds": 120}, "同一进程在短时间内读取多个不同敏感路径，构成聚合 Collection 证据。", (key, int(first.event_time.timestamp() // 120))))
                    break
        return results


class CollectionArchiveCorrelationRule:
    rule_id = "det.host.collection_archive_correlation"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        reads = [event for event in events if event.action == "file.read" and SensitiveFileCollectionRule._matches_sensitive_path(_path(event))]
        archives = [event for event in events if event.action == "process.start" and _is_archiver(event)]
        results = []
        for archive in archives:
            related = [item for item in reads if _host_id(item) == _host_id(archive) and _within(archive, item, 300) and (_process_related(item, archive) or _process_id(item) == _process_id(archive))]
            if related:
                selected = related[:40] + [archive]
                results.append(_detection(run_id, self.rule_id, self.version, "敏感读取后归档", "correlation", "high", 0.84, selected, evidence, {"archive_command": _command_line(archive), "sensitive_reads": len(related), "window_seconds": 300}, "敏感路径读取后，同主机/进程谱系出现 tar/zip/gzip 等归档行为，形成收集到打包的可解释关联。", (_host_id(archive), _process_id(archive), int(archive.event_time.timestamp() // 300))))
        return results


class ArchiveTransferCorrelationRule:
    rule_id = "det.network.archive_transfer_correlation"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        reads = [event for event in events if event.action == "file.read" and SensitiveFileCollectionRule._matches_sensitive_path(_path(event))]
        archives = [event for event in events if event.action == "process.start" and _is_archiver(event)]
        transfers = [event for event in events if event.network and event.action in {"network.send", "network.connect", "network.file_transfer", "http.request"}]
        results = []
        for archive in archives:
            prior_reads = [item for item in reads if _host_id(item) == _host_id(archive) and _within(archive, item, 300)]
            for transfer in transfers:
                if not _within(transfer, archive, 300) or _host_id(transfer) != _host_id(archive):
                    continue
                upload = (transfer.network.bytes_sent or 0) >= 50000 or transfer.action == "network.file_transfer" or (transfer.network.http and str(transfer.network.http.get("method") or "").upper() in {"POST", "PUT"})
                if upload or (_is_unexpected_peer(transfer) and prior_reads):
                    selected = prior_reads[:30] + [archive, transfer]
                    results.append(_detection(run_id, self.rule_id, self.version, "归档后外传关联", "correlation", "critical", 0.86, selected, evidence, {"bytes_sent": transfer.network.bytes_sent, "peer": _canonical_peer_key(transfer), "archive_command": _command_line(archive)}, "敏感收集/归档后在有限窗口内出现大量出站传输、HTTP 上传或已确认异常 peer 会话，证据同时引用 collection、archive 与 network。", (_host_id(archive), _process_id(archive), _canonical_peer_key(transfer))))
                    break
        return results


class IngressToolTransferRule:
    rule_id = "det.host.ingress_tool_transfer"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        network_in = [event for event in events if event.network and event.action in {"network.receive", "network.connect"}]
        writes = [event for event in events if event.action in {"file.open", "file.write", "file.create"} and _is_temp_path(_path(event))]
        starts = [event for event in events if event.action == "process.start" and _is_temp_path(_path(event))]
        results = []
        for write in writes:
            inbound = [item for item in network_in if _host_id(item) == _host_id(write) and _within(write, item, 120) and (_process_related(item, write) or _process_id(item) == _process_id(write))]
            executed = [item for item in starts if _host_id(item) == _host_id(write) and _path(item) == _path(write) and _within(item, write, 180)]
            if inbound and executed:
                selected = inbound[:10] + [write, executed[0]]
                results.append(_detection(run_id, self.rule_id, self.version, "外部接收后工具落地执行", "correlation", "high", 0.84, selected, evidence, {"path": _path(write), "network_events": len(inbound), "window_seconds": 180}, "外部网络接收/连接后，同主机进程谱系将文件写入临时目录并执行，满足工具传入的落地和执行链。", (_host_id(write), _path(write), int(write.event_time.timestamp() // 180))))
        return results


class SuspiciousFileStagingRule:
    rule_id = "det.host.suspicious_file_staging"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        grouped = defaultdict(list)
        for event in events:
            path = _path(event)
            if path and _is_temp_path(path) and event.action in {"file.create", "file.open", "file.write", "file.modify", "process.start"}:
                grouped[(_host_id(event), path)].append(event)
        results = []
        for key, items in grouped.items():
            items.sort(key=lambda item: item.event_time)
            prep = [item for item in items if item.action in {"file.create", "file.open", "file.write", "file.modify"}]
            if len({item.action for item in prep}) < 2:
                continue
            exec_or_parent = [item for item in items if item.action == "process.start" or _is_service_name(_parent_name(item))]
            if exec_or_parent:
                selected = prep[:30] + exec_or_parent[:3]
                results.append(_detection(run_id, self.rule_id, self.version, "临时文件连续暂存准备", "correlation", "medium", 0.76, selected, evidence, {"path": key[1], "preparation_actions": sorted({item.action for item in prep}), "has_execute_or_high_risk_parent": True}, "临时目录同一文件出现连续 create/open/write/chmod 准备动作，并随后执行或与高风险服务父进程相关，单个 open/write 不触发。", key))
        return results


class ForkExecTempRule:
    rule_id = "det.host.fork_exec_temp"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        forks = [event for event in events if event.action == "process.start" and _dataset_value(event, "original_action") in {"aue_fork", "aue_vfork"}]
        execs = [event for event in events if event.action == "process.start" and _dataset_value(event, "original_action") == "aue_execve"]
        results = []
        for fork in forks:
            matches = [item for item in execs if _host_id(item) == _host_id(fork) and _within(item, fork, 30) and (_process_related(fork, item) or _parent_id(item) == _process_id(fork))]
            risky = [item for item in matches if _is_temp_path(_path(item)) or _is_shell_or_interpreter(_process_name(item)) or _is_service_name(_parent_name(item))]
            if risky:
                selected = [fork, risky[0]]
                results.append(_detection(run_id, self.rule_id, self.version, "fork 后异常 exec", "correlation", "medium", 0.74, selected, evidence, {"path": _path(risky[0]), "child": _process_name(risky[0]), "window_seconds": 30}, "fork/vfork 后短时间内 exec 临时目录文件、解释器或服务进程子链；普通 fork/exec 不触发。", (_host_id(fork), _process_id(fork), risky[0].event_id)))
        return results


class RegistryPersistenceRule:
    rule_id = "det.host.registry_persistence"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            path = str(event.object.ref.display_name if event.object.ref else "").lower()
            if not event.action.startswith("registry.") or not any(marker in path for marker in ("\\run", "\\runonce", "winlogon", "services")):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="注册表持久化位置变更", detector_type="rule", severity="high", confidence=0.87, event_ids=event_ids, entity_ids=refs, feature_values={"registry_path": path, "action": event.action}, reason="Sysmon 记录到常见自启动注册表位置被创建或修改。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results
