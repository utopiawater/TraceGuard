from typing import Dict, List

from app.contracts import AttackMapping, DetectionResult, Evidence, Session, UnifiedSecurityEvent
from app.core.ids import stable_id


def _evidence_for(event_ids: List[str], evidence: List[Evidence]) -> List[str]:
    wanted = set(event_ids)
    return sorted({item.evidence_id for item in evidence if wanted.intersection(item.event_ids)})


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
            results.append(DetectionResult(
                detection_id=stable_id("det", self.rule_id, self.version, event.event_id), run_id=run_id,
                rule_id=self.rule_id, rule_version=self.version, title="远程交互式登录", detector_type="rule",
                severity="medium", confidence=0.78, event_ids=[event.event_id], entity_ids=refs,
                session_ids=[event.object.ref.entity_id] if event.object.ref else [],
                feature_values={"logon_type": fields.get("LogonType"), "source_ip": fields.get("IpAddress")},
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
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="权限提升或高权限令牌分配", detector_type="rule", severity="high", confidence=0.9, event_ids=event_ids, entity_ids=sorted(set(refs)), feature_values={"action": event.action, "privileges": fields.get("PrivilegeList"), "uid": fields.get("uid"), "euid": fields.get("euid")}, reason="操作系统审计记录证明账户获得高权限令牌或有效身份发生提升。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results


class SensitiveFileCollectionRule:
    rule_id = "det.host.sensitive_file_collection"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        markers = ("/etc/shadow", "/etc/passwd", "\\sam", "documents", "secrets", "credentials", ".ssh")
        for event in events:
            path = str((event.object.ref.attributes.get("normalized_path") if event.object.ref else "") or "").lower()
            if event.action != "file.read" or not any(marker in path for marker in markers):
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="敏感文件访问与收集", detector_type="rule", severity="high", confidence=0.88, event_ids=event_ids, entity_ids=refs, feature_values={"path": path, "operation": event.action}, reason="进程读取了凭据或业务敏感路径，可作为后续暂存与外传的数据来源证据。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
        return results


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


class MemoryTamperingRule:
    rule_id = "det.host.memory_tampering"
    version = "1.0.0"

    def evaluate(self, run_id, events, sessions, evidence):
        results = []
        for event in events:
            if event.action not in {"memory.remote_thread", "memory.process_access", "memory.process_tamper"}:
                continue
            event_ids = [event.event_id]
            refs = [ref.entity_id for ref in (event.host, event.actor.process, event.object.ref) if ref]
            results.append(DetectionResult(detection_id=stable_id("det", self.rule_id, event.event_id), run_id=run_id, rule_id=self.rule_id, rule_version=self.version, title="代表性内存篡改行为", detector_type="rule", severity="high", confidence=0.84, event_ids=event_ids, entity_ids=refs, feature_values={"sysmon_event_id": event.extensions.get("event_id"), "action": event.action}, reason="Sysmon 记录到远程线程、跨进程访问或进程篡改事件。", attack_mappings=[], evidence_ids=_evidence_for(event_ids, evidence), created_at=event.event_time))
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
