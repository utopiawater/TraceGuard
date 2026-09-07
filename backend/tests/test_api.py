from fastapi.testclient import TestClient
from pathlib import Path

from app.bootstrap import build_pipeline
from app.core.settings import Settings
from app.main import create_app
from app.scenarios import load_scenario


def test_health_and_empty_resources_are_explicit(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "api.db", raw_archive_dir=tmp_path / "raw")
    client = TestClient(create_app(settings))
    health = client.get("/api/system/health")
    assert health.status_code == 200
    assert health.json()["data"]["status"] == "ok"
    agents = client.get("/api/agents").json()
    assert agents["data"] == []
    assert "尚未接入" in agents["meta"]["warnings"][0]


def test_agent_attribution_and_report_resources_use_persisted_results(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "api-agent.db", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False, llm_base_url="", llm_api_key="", llm_model="")
    app = create_app(settings)
    chain = build_pipeline(settings, app.state.repository, app.state.graph).run("run_api_agent", load_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain")).chains[0]
    with TestClient(app) as client:
        started = client.post("/api/chains/%s/investigate" % chain.chain_id)
        assert started.status_code == 200
        case_id = started.json()["data"]["case_id"]
        agents = client.get("/api/agents").json()["data"]
        assert agents[0]["case_id"] == case_id
        assert client.get("/api/agents/%s" % case_id).json()["data"]["tasks"][-1]["agent_role"] == "report"
        assert client.get("/api/attribution").json()["data"][0]["status"] == "unable_to_attribute"
        reports = client.get("/api/reports").json()["data"]
        assert {item["format"] for item in reports} == {"markdown", "html"}
        assert client.get(reports[0]["export_url"]).status_code == 200
