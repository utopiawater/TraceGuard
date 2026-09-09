import ipaddress
import json
import ntpath
import os
import posixpath
from pathlib import Path
from collections import defaultdict
from fnmatch import fnmatch
from typing import Dict, List

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
            refs = sorted({ref.entity_id for item in items[:20] for ref in (item.host, item.object.ref) if ref})
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
