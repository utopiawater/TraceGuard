import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.agents.harness import Tool, ToolGateway, default_agent_registry
from app.bootstrap import build_pipeline
from app.contracts import AgentTask
from app.core.settings import Settings
from app.graph import InMemoryGraphProjector
from app.repositories import SQLiteRepository
from app.scenarios import load_scenario


def main() -> None:
    checks = []
    scenario = ROOT / "backend" / "fixtures" / "scenarios" / "powershell_cross_source"
    raws = load_scenario(scenario)
    assert len(raws) == 4 and len({raw.raw_id for raw in raws}) == 4
    checks.append("4 条真实格式 raw envelope 与确定性 ID")
    with tempfile.TemporaryDirectory(prefix="traceguard-check-") as temp:
        data = Path(temp)
        settings = Settings(data_dir=data, database_path=data / "check.db", raw_archive_dir=data / "raw")
        repository = SQLiteRepository(settings.database_path)
        graph = InMemoryGraphProjector()
        pipeline = build_pipeline(settings, repository, graph)
        result = pipeline.run("run_self_check", raws)
        assert [event.action for event in result.events] == ["auth.logon", "process.start", "network.connect", "network.flow"]
        checks.append("Windows Security / Sysmon / Zeek Adapter")
        assert len(result.sessions) == 3
        checks.append("登录与网络 Session")
        assert [item.rule_id for item in result.detections] == ["det.auth.remote_interactive_logon", "det.host.suspicious_powershell", "det.network.cross_source_interpreter_connection"]
        checks.append("规则注册、双源关联与 DetectionResult")
        assert len(result.chains) == 1 and result.chains[0].technique_ids == ["T1078", "T1059.001", "T1071.001"]
        assert all(step.evidence_ids for step in result.chains[0].steps)
        checks.append("ATT&CK 映射、AttackChain 与 Evidence 外键")
        required_relations = {"SPAWNED", "INITIATED", "FROM", "TO", "USED_TECHNIQUE"}
        assert required_relations.issubset({item.relation_type for item in result.graph_relations})
        checks.append("实体解析与图投影")
        before = repository.counts()
        replay = pipeline.run("run_self_check", raws)
        assert replay.accepted_raw == 0 and repository.counts() == before
        checks.append("同一输入重放幂等")
    registry = default_agent_registry()
    gateway = ToolGateway([Tool("event_search", lambda args: {"refs": []})])
    task = AgentTask(task_id="task_self_check", case_id="case_self_check", agent_role="host", objective="check", allowed_tools=["event_search"], constraints={"max_steps": 2, "deadline_ms": 1000, "read_only": True})
    assert gateway.invoke(task, registry, "event_search", {}) == {"refs": []}
    try:
        gateway.invoke(task, registry, "intel_lookup", {})
        raise AssertionError("tool permission was not enforced")
    except PermissionError:
        pass
    checks.append("Agent role/task 双重工具权限")
    print(json.dumps({"status": "passed", "checks": len(checks), "details": checks}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
