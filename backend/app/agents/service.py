import html
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple
from uuid import uuid4

from app.agents.harness import EvidenceValidator, default_agent_registry
from app.agents.model import OpenAICompatibleModelClient
from app.agents.tools import build_tool_gateway
from app.contracts import AgentFinding, AgentResult, AgentTask, AttackChain, DetectionResult
from app.contracts.agents import AgentConstraints, ModelInfo, StructuredError
from app.core.ids import stable_id
from app.core.time import utc_now
from app.knowledge import MappingFileProvider
from app.repositories import SQLiteRepository


HOST_RULE_PREFIXES = ("det.host.", "det.auth.")
NETWORK_RULE_PREFIXES = ("det.network.",)


class InvestigationService:
    def __init__(self, repo: SQLiteRepository, graph, settings) -> None:
        self.repo, self.graph, self.settings = repo, graph, settings
        self.attack = MappingFileProvider(Path(__file__).parents[3] / "knowledge" / "attack" / "mappings.json")
        self.registry = default_agent_registry()
        self.gateway = build_tool_gateway(repo, graph, self.attack)
        self.validator = EvidenceValidator()
        self.model = OpenAICompatibleModelClient(
            settings.llm_base_url, settings.llm_api_key, settings.llm_model, settings.llm_timeout_seconds,
        )
        self._task_runtime: Dict[str, dict] = {}

    def investigate(
        self,
        chain_id: str,
        case_id: Optional[str] = None,
        scope: Literal["full", "quick"] = "full",
        max_steps: int = 12,
    ) -> dict:
        chain = self.repo.get_chain(chain_id)
        if not chain:
            raise ValueError("attack chain not found")
        if scope not in {"full", "quick"}:
            raise ValueError("unsupported investigation scope")
        case_id = case_id or "case_%s" % uuid4().hex[:16]
        created = utc_now().isoformat()
        quick = scope == "quick"

        coordinator = self._new_task(case_id, "coordinator", "为既有攻击链分解调查任务并监督执行状态", [chain_id], None, max_steps)
        self._queue(coordinator, chain_id, created, scope)
        coordinator_result, _ = self._guarded(coordinator, chain, self._run_coordinator, quick)

        host = self._new_task(case_id, "host", "核查登录、用户、进程、文件、注册表、权限及内存证据", [chain_id], coordinator.task_id, max_steps)
        network = self._new_task(case_id, "network", "核查会话、Zeek、DNS、HTTP、ICMP、C2 与隐蔽信道证据", [chain_id], coordinator.task_id, max_steps)
        self._queue(host, chain_id, created, scope)
        self._queue(network, chain_id, created, scope)
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="traceguard-agent") as executor:
            host_future = executor.submit(self._guarded, host, chain, self._run_host, quick)
            network_future = executor.submit(self._guarded, network, chain, self._run_network, quick)
            host_result, host_artifact = host_future.result()
            network_result, network_artifact = network_future.result()

        correlation = self._new_task(case_id, "correlation", "审阅既有七阶段攻击链、关系路径、替代解释与证据缺口", [chain_id, host_result.result_id, network_result.result_id], coordinator.task_id, max_steps)
        self._queue(correlation, chain_id, created, scope)
        correlation_result, correlation_artifact = self._guarded(correlation, chain, self._run_correlation, host_result, network_result)

        if quick:
            return self._summary(
                case_id, chain_id, created, scope,
                [coordinator, host, network, correlation],
                [coordinator_result, host_result, network_result, correlation_result],
                [],
            )

        attribution = self._new_task(case_id, "attribution", "基于固定 ATT&CK 知识与已验证证据进行候选相似性分析", [chain_id, correlation_result.result_id], correlation.task_id, max_steps)
        self._queue(attribution, chain_id, created, scope)
        attribution_result, attribution_artifact = self._guarded(attribution, chain, self._run_attribution)

        report = self._new_task(case_id, "report", "仅使用已验证 Findings、攻击链、ATT&CK 与证据生成调查报告", [chain_id, host_result.result_id, network_result.result_id, correlation_result.result_id, attribution_result.result_id], attribution.task_id, max_steps)
        self._queue(report, chain_id, created, scope)
        accepted = [host_result, network_result, correlation_result, attribution_result]
        report_result, report_artifact = self._guarded(report, chain, self._run_report, accepted, attribution_artifact)

        results = [coordinator_result, host_result, network_result, correlation_result, attribution_result, report_result]
        return self._summary(
            case_id, chain_id, created, scope,
            [coordinator, host, network, correlation, attribution, report], results,
            report_artifact.get("report_ids", []),
        )

    def _summary(self, case_id: str, chain_id: str, created: str, scope: str, tasks: List[AgentTask], results: List[AgentResult], report_ids: List[str]) -> dict:
        failed = [item for item in results if item.status == "failed"]
        partial = [item for item in results if item.status == "partial"]
        findings = [finding for result in results for finding in result.findings]
        confidence = round(sum(item.confidence for item in findings) / len(findings), 4) if findings else 0.0
        return {
            "case_id": case_id, "chain_id": chain_id,
            "status": "failed" if len(failed) == len(results) else ("partial" if failed or partial else "succeeded"),
            "created_at": created, "finished_at": utc_now().isoformat(), "final_confidence": confidence,
            "scope": scope, "task_ids": [item.task_id for item in tasks], "report_ids": report_ids,
            "model": {"configured": self.model.configured, "model": self.settings.llm_model or "deterministic-fallback"},
        }

    def _new_task(self, case_id: str, role: str, objective: str, refs: List[str], parent: Optional[str], max_steps: int) -> AgentTask:
        definition = self.registry.get(role)
        return AgentTask(
            task_id="task_%s" % uuid4().hex[:20], case_id=case_id, agent_role=role, objective=objective,
            input_refs=refs, allowed_tools=sorted(definition.allowed_tools),
            constraints=AgentConstraints(max_steps=max_steps, deadline_ms=60000, read_only=True), parent_task_id=parent, state="queued",
        )

    def _queue(self, task: AgentTask, chain_id: str, created: str, scope: str) -> None:
        runtime = {"investigation_id": task.case_id, "chain_id": chain_id, "scope": scope, "created_at": created, "status_history": [{"status": "queued", "at": created}]}
        self._task_runtime[task.task_id] = runtime
        self.repo.put_agent_task(task, runtime)

    def _start(self, task: AgentTask, chain_id: str) -> Tuple[AgentTask, str]:
        started = utc_now().isoformat()
        running = task.model_copy(update={"state": "running"})
        runtime = dict(self._task_runtime.get(task.task_id, {"investigation_id": task.case_id, "chain_id": chain_id, "created_at": started, "status_history": []}))
        runtime.update({"started_at": started})
        runtime["status_history"] = list(runtime.get("status_history", [])) + [{"status": "running", "at": started}]
        self._task_runtime[task.task_id] = runtime
        self.repo.put_agent_task(running, runtime)
        self.gateway.clear_audit(task.task_id)
        return running, started

    def _guarded(self, task: AgentTask, chain: AttackChain, handler, *args) -> Tuple[AgentResult, dict]:
        try:
            return handler(task, chain, *args)
        except Exception as exc:
            finished = utc_now().isoformat()
            failed_task = task.model_copy(update={"state": "failed"})
            runtime = dict(self._task_runtime.get(task.task_id, {"investigation_id": task.case_id, "chain_id": chain.chain_id, "created_at": finished, "status_history": []}))
            runtime.update({"finished_at": finished, "error": str(exc)})
            runtime["status_history"] = list(runtime.get("status_history", [])) + [{"status": "failed", "at": finished}]
            self._task_runtime[task.task_id] = runtime
            self.repo.put_agent_task(failed_task, runtime)
            result = AgentResult(
                result_id=stable_id("agent_result", task.task_id), task_id=task.task_id, status="failed", findings=[],
                tool_calls=self.gateway.audit_for(task.task_id), output_refs=[],
                errors=[StructuredError(code="agent_execution_failed", message=str(exc), retryable=False)],
                model_info=ModelInfo(provider="deterministic", model="fallback-v1", prompt_version=self.registry.get(task.agent_role).prompt_version),
            )
            self.repo.put_agent_result(result, {}, {"finished_at": finished, "fallback": True})
            return result, {}

    def _invoke(self, task: AgentTask, name: str, arguments: dict) -> dict:
        return self.gateway.invoke(task, self.registry, name, arguments)

    def _finish(self, task: AgentTask, chain: AttackChain, draft: AgentResult, context: dict, artifact: Optional[dict] = None) -> AgentResult:
        evidence_ids = {item.evidence_id for item in self.repo.list_evidence(10000)}
        used_fallback, fallback_message, token_usage = False, None, {}
        try:
            payload = self.model.complete_json(
                task.agent_role, self.registry.get(task.agent_role).prompt_version,
                {"instruction": "Refine the verified draft without changing identifiers or introducing facts.", "verified_context": context, "draft": draft.model_dump(mode="json")},
                AgentResult.model_json_schema(),
            )
            if hasattr(self.model, "last_usage"):
                token_usage = self.model.last_usage()
            result = AgentResult.model_validate(payload)
            if result.task_id != task.task_id or result.result_id != draft.result_id:
                raise ValueError("model changed immutable task/result identifiers")
            result = result.model_copy(update={
                "tool_calls": self.gateway.audit_for(task.task_id),
                "model_info": ModelInfo(provider="openai-compatible", model=self.settings.llm_model, prompt_version=self.registry.get(task.agent_role).prompt_version),
            })
            errors = self.validator.validate(result, evidence_ids)
            if errors:
                raise ValueError("; ".join(errors))
        except Exception as exc:
            used_fallback, fallback_message = True, str(exc)
            result = draft.model_copy(update={
                "tool_calls": self.gateway.audit_for(task.task_id),
                "errors": list(draft.errors) + [StructuredError(code="model_fallback", message=fallback_message, retryable=True)],
                "model_info": ModelInfo(provider="deterministic", model="fallback-v1", prompt_version=self.registry.get(task.agent_role).prompt_version),
            })
            errors = self.validator.validate(result, evidence_ids)
            if errors:
                raise ValueError("deterministic result failed evidence validation: %s" % "; ".join(errors))
        finished = utc_now().isoformat()
        completed = task.model_copy(update={"state": "succeeded" if result.status != "failed" else "failed"})
        runtime = dict(self._task_runtime.get(task.task_id, {"investigation_id": task.case_id, "chain_id": chain.chain_id, "created_at": finished, "status_history": []}))
        runtime.update({"finished_at": finished, "model_fallback": used_fallback, "error": fallback_message, "token_usage": token_usage})
        runtime["status_history"] = list(runtime.get("status_history", [])) + [{"status": result.status, "at": finished}]
        self._task_runtime[task.task_id] = runtime
        self.repo.put_agent_task(completed, runtime)
        self.repo.put_agent_result(result, artifact or {}, {"finished_at": finished, "fallback": used_fallback, "token_usage": token_usage})
        return result

    def _draft(self, task: AgentTask, findings: List[AgentFinding], output_refs: Optional[List[str]] = None, status: str = "succeeded") -> AgentResult:
        return AgentResult(
            result_id=stable_id("agent_result", task.task_id), task_id=task.task_id, status=status,
            findings=findings, tool_calls=[], output_refs=output_refs or [], errors=[],
            model_info=ModelInfo(provider="deterministic", model="fallback-v1", prompt_version=self.registry.get(task.agent_role).prompt_version),
        )

    def _run_coordinator(self, task: AgentTask, chain: AttackChain, quick: bool = False) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        chain_data = self._invoke(running, "chain_lookup", {"chain_id": chain.chain_id})
        source_data = self._invoke(running, "source_health", {"limit": 50})
        detection_data = self._invoke(running, "detection_lookup", {"ids": chain.detection_ids[:50]}) if not quick else {"detections": []}
        evidence = chain.evidence_ids[:50]
        findings = [AgentFinding(
            claim="已锁定既有攻击链并创建主机与网络并行调查分支；后续关联只审阅原有 %d 个步骤。" % len(chain.steps),
            confidence=chain.score, evidence_ids=evidence, alternatives=list(chain.uncertainties[:3]),
        )]
        draft = self._draft(running, findings, [chain.chain_id] + chain.detection_ids)
        artifact = {"scope": "quick" if quick else "full", "plan": ["host", "network", "correlation"] if quick else ["host", "network", "correlation", "attribution", "report"]}
        return self._finish(running, chain, draft, {"chain": chain_data, "sources": source_data, "detections": detection_data}, artifact), artifact

    def _run_host(self, task: AgentTask, chain: AttackChain, quick: bool = False) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        detections = [item for item in self.repo.list_detections(5000) if item.run_id == chain.run_id and item.rule_id.startswith(HOST_RULE_PREFIXES)]
        detection_data = self._invoke(running, "detection_lookup", {"ids": [item.detection_id for item in detections]}) if detections else {"detections": []}
        actions = ["auth.", "process.", "file.", "registry.", "privilege.", "memory."]
        event_data = self._invoke(running, "event_search", {"actions": actions, "limit": 60 if quick else 200})
        session_data = {"sessions": [], "count": 0} if quick else self._invoke(running, "session_lookup", {"session_type": "login", "limit": 100})
        timeline_data = {"events": []} if quick else (self._invoke(running, "entity_timeline", {"entity_id": chain.entity_ids[0], "limit": 100}) if chain.entity_ids else {"events": []})
        graph_data = {"nodes": [], "edges": []} if quick else (self._invoke(running, "graph_neighbors", {"entity_id": chain.entity_ids[0], "depth": 2, "limit": 100}) if chain.entity_ids else {"nodes": [], "edges": []})
        evidence_ids = sorted({evidence for item in detections for evidence in item.evidence_ids})
        evidence_data = self._invoke(running, "evidence_get", {"ids": evidence_ids[:50]}) if evidence_ids else {"evidence": []}
        findings = [self._detection_finding(item) for item in detections]
        draft = self._draft(running, findings, [item.detection_id for item in detections], "succeeded" if findings else "partial")
        artifact = {"domains": ["login", "user", "process", "file", "registry", "privilege", "memory"], "event_count": event_data["count"], "session_count": session_data["count"]}
        result = self._finish(running, chain, draft, {"detections": detection_data, "events": event_data, "sessions": session_data, "timeline": timeline_data, "graph": graph_data, "evidence": evidence_data}, artifact)
        return result, artifact

    def _run_network(self, task: AgentTask, chain: AttackChain, quick: bool = False) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        detections = [item for item in self.repo.list_detections(5000) if item.run_id == chain.run_id and item.rule_id.startswith(NETWORK_RULE_PREFIXES)]
        detection_data = self._invoke(running, "detection_lookup", {"ids": [item.detection_id for item in detections]}) if detections else {"detections": []}
        event_data = self._invoke(running, "event_search", {"actions": ["network.", "dns.", "http.", "icmp."], "source_kinds": ["zeek"], "limit": 60 if quick else 200})
        session_data = {"sessions": [], "count": 0} if quick else self._invoke(running, "session_lookup", {"session_type": "network", "limit": 100})
        graph_data = {"nodes": [], "edges": []} if quick else (self._invoke(running, "graph_neighbors", {"entity_id": chain.entity_ids[-1], "depth": 2, "limit": 100}) if chain.entity_ids else {"nodes": [], "edges": []})
        evidence_ids = sorted({evidence for item in detections for evidence in item.evidence_ids})
        evidence_data = self._invoke(running, "evidence_get", {"ids": evidence_ids[:50]}) if evidence_ids else {"evidence": []}
        findings = [self._detection_finding(item) for item in detections]
        draft = self._draft(running, findings, [item.detection_id for item in detections], "succeeded" if findings else "partial")
        covert = [item.rule_id for item in detections if "tunnel" in item.rule_id or "covert" in item.rule_id]
        artifact = {"domains": ["conn", "dns", "http", "icmp", "c2", "covert_channel"], "event_count": event_data["count"], "session_count": session_data["count"], "covert_detections": covert}
        result = self._finish(running, chain, draft, {"detections": detection_data, "events": event_data, "sessions": session_data, "graph": graph_data, "evidence": evidence_data}, artifact)
        return result, artifact

    def _run_correlation(self, task: AgentTask, chain: AttackChain, host: AgentResult, network: AgentResult) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        chain_data = self._invoke(running, "chain_lookup", {"chain_id": chain.chain_id})
        validation = self._invoke(running, "chain_validate", {"chain_id": chain.chain_id})
        path = {"found": False, "relations": []}
        if len(chain.entity_ids) >= 2:
            path = self._invoke(running, "graph_path", {"source_entity_id": chain.entity_ids[0], "target_entity_id": chain.entity_ids[-1], "max_depth": 6})
        findings = [AgentFinding(
            claim="链步骤“%s”保持为确定性主管道生成结果；Agent 仅验证其时间、检测、实体、证据和前驱引用。" % step.stage,
            confidence=step.score, evidence_ids=step.evidence_ids,
            alternatives=list(chain.uncertainties[:2]) or ["相邻步骤仍需结合原始记录排除时间接近但无因果关系的解释"],
        ) for step in chain.steps]
        status = "succeeded" if validation["valid"] else "partial"
        draft = self._draft(running, findings, [chain.chain_id], status)
        artifact = {"chain_valid": validation["valid"], "validation_errors": validation["errors"], "bounded_path_found": path["found"], "bounded_path_depth": path.get("depth"), "host_status": host.status, "network_status": network.status, "evidence_gaps": chain.uncertainties}
        result = self._finish(running, chain, draft, {"chain": chain_data, "validation": validation, "bounded_path": path, "host_findings": self._accepted(host), "network_findings": self._accepted(network)}, artifact)
        return result, artifact

    def _run_attribution(self, task: AgentTask, chain: AttackChain) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        chain_data = self._invoke(running, "chain_lookup", {"chain_id": chain.chain_id})
        attack_data = self._invoke(running, "attack_lookup", {"technique_ids": chain.technique_ids[:20]})
        evidence_data = self._invoke(running, "evidence_get", {"ids": chain.evidence_ids[:50]})
        claim = "当前证据能够描述 ATT&CK TTP 与网络/主机行为，但没有足够独有 IOC 或工具指纹将事件可靠归因到具体组织。"
        finding = AgentFinding(claim=claim, confidence=0.92, evidence_ids=chain.evidence_ids[:50], alternatives=["多个攻击组织及通用渗透工具均可能产生相同 TTP 组合"])
        draft = self._draft(running, [finding], [chain.chain_id] + chain.technique_ids)
        candidate_rows = []
        for group in attack_data.get("groups", []):
            overlap = sorted(set(chain.technique_ids) & set(group.get("technique_ids", [])))
            union = set(chain.technique_ids) | set(group.get("technique_ids", []))
            similarity = round(len(overlap) / len(union), 4) if union else 0
            candidate_rows.append({
                "candidate": "%s (%s)" % (group["name"], group["group_id"]), "similarity": similarity,
                "technique_overlap": overlap, "c2_ioc_evidence": [],
                "supporting_evidence": sorted({e for step in chain.steps if step.technique_id in overlap for e in step.evidence_ids}),
                "counter_evidence": ["只有通用 TTP 重合；没有该组织专属基础设施、恶意软件或行动指纹"],
                "confidence": min(0.49, similarity),
            })
        artifact = {
            "status": "unable_to_attribute", "label": "无法可靠归因",
            "candidates": sorted(candidate_rows, key=lambda item: item["similarity"], reverse=True)[:3], "technique_overlap": chain.technique_ids,
            "c2_ioc_evidence": chain.evidence_ids[:20], "supporting_evidence": chain.evidence_ids[:20],
            "counter_evidence": ["缺少可唯一识别组织的基础设施归属、恶意软件家族或签名证据"],
            "confidence": 0.92, "wording": "归因候选 / 相似性分析",
        }
        result = self._finish(running, chain, draft, {"chain": chain_data, "attack": attack_data, "evidence": evidence_data}, artifact)
        return result, artifact

    def _run_report(self, task: AgentTask, chain: AttackChain, accepted: List[AgentResult], attribution: dict) -> Tuple[AgentResult, dict]:
        running, _ = self._start(task, chain.chain_id)
        chain_data = self._invoke(running, "chain_lookup", {"chain_id": chain.chain_id})
        accepted_findings = [finding for result in accepted if result.status != "failed" for finding in result.findings]
        evidence_ids = sorted({item for finding in accepted_findings for item in finding.evidence_ids})
        evidence_data = self._invoke(running, "evidence_get", {"ids": evidence_ids[:50]})
        sections = self._report_sections(chain, accepted, attribution)
        report_ids = self._persist_reports(task.case_id, chain, sections, evidence_ids)
        finding = AgentFinding(claim="调查报告已由通过 EvidenceValidator 的 Findings 生成，未重新调查或新增攻击链步骤。", confidence=chain.score, evidence_ids=evidence_ids, alternatives=list(chain.uncertainties[:3]))
        draft = self._draft(running, [finding], report_ids)
        artifact = {"sections": sections, "report_ids": report_ids, "evidence_count": len(evidence_ids), "source_task_ids": [result.task_id for result in accepted]}
        result = self._finish(running, chain, draft, {"chain": chain_data, "accepted_findings": [item.model_dump(mode="json") for item in accepted_findings], "evidence": evidence_data, "attribution": attribution}, artifact)
        return result, artifact

    @staticmethod
    def _detection_finding(detection: DetectionResult) -> AgentFinding:
        alternatives = []
        if detection.confidence < 0.9:
            alternatives.append("该行为也可能由经过授权的管理或测试活动产生")
        return AgentFinding(claim="%s：%s" % (detection.title, detection.reason), confidence=detection.confidence, evidence_ids=detection.evidence_ids, alternatives=alternatives)

    @staticmethod
    def _accepted(result: AgentResult) -> List[dict]:
        return [item.model_dump(mode="json") for item in result.findings] if result.status != "failed" else []

    @staticmethod
    def _report_sections(chain: AttackChain, results: List[AgentResult], attribution: dict) -> dict:
        findings = [finding for result in results if result.status != "failed" for finding in result.findings]
        timeline = [{"time": step.start_time.isoformat(), "stage": step.stage, "technique_id": step.technique_id, "evidence_ids": step.evidence_ids} for step in chain.steps]
        return {
            "事件摘要": {"text": chain.title, "confidence": chain.score, "evidence_ids": chain.evidence_ids},
            "调查范围": {"text": "既有攻击链、主机行为、网络会话、检测、ATT&CK 与图关系", "evidence_ids": chain.evidence_ids},
            "攻击时间线": timeline,
            "攻击链": [{"stage": step.stage, "technique_id": step.technique_id, "explanation": step.explanation, "evidence_ids": step.evidence_ids} for step in chain.steps],
            "ATT&CK": [{"technique_id": item, "evidence_ids": sorted({e for step in chain.steps if step.technique_id == item for e in step.evidence_ids})} for item in chain.technique_ids],
            "主机分析": [item.model_dump(mode="json") for item in results[0].findings] if results else [],
            "网络分析": [item.model_dump(mode="json") for item in results[1].findings] if len(results) > 1 else [],
            "攻击归因候选": attribution,
            "证据": [{"evidence_id": evidence_id} for evidence_id in sorted({e for finding in findings for e in finding.evidence_ids})],
            "不确定项": chain.uncertainties or ["当前链未记录额外不确定项"],
            "安全建议": ["隔离链中受影响主机并保全原始证据", "轮换被关联账户凭据并复核远程登录来源", "阻断已确认的 C2/外传目标并持续监控 DNS、HTTP、ICMP 异常"],
        }

    def _persist_reports(self, case_id: str, chain: AttackChain, sections: dict, evidence_ids: List[str]) -> List[str]:
        created = utc_now().isoformat()
        markdown_id = stable_id("report", case_id, "markdown")
        html_id = stable_id("report", case_id, "html")
        markdown_path = self.settings.report_dir / (markdown_id + ".md")
        html_path = self.settings.report_dir / (html_id + ".html")
        markdown = self._markdown(sections)
        markdown_path.write_text(markdown, encoding="utf-8")
        html_path.write_text("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><title>%s</title><style>body{font:15px/1.65 system-ui;max-width:960px;margin:40px auto;padding:0 24px;color:#24303b}h1,h2{letter-spacing:-.02em}code{background:#f3f4f5;padding:2px 5px;border-radius:4px}</style><body>%s</body></html>" % (html.escape(chain.title), self._html(sections)), encoding="utf-8")
        self.repo.put_report(markdown_id, case_id, chain.run_id, "markdown", "1.0", str(markdown_path.resolve()), evidence_ids, created)
        self.repo.put_report(html_id, case_id, chain.run_id, "html", "1.0", str(html_path.resolve()), evidence_ids, created)
        return [markdown_id, html_id]

    @staticmethod
    def _markdown(sections: dict) -> str:
        lines = ["# TraceGuard Agent 调查报告", ""]
        for title, value in sections.items():
            lines.extend(["## %s" % title, "", "```json", json.dumps(value, ensure_ascii=False, indent=2), "```", ""])
        return "\n".join(lines)

    @staticmethod
    def _html(sections: dict) -> str:
        parts = ["<h1>TraceGuard Agent 调查报告</h1>"]
        for title, value in sections.items():
            parts.append("<h2>%s</h2><pre>%s</pre>" % (html.escape(title), html.escape(json.dumps(value, ensure_ascii=False, indent=2))))
        return "".join(parts)
