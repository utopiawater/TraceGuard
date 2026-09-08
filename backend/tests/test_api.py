from fastapi.testclient import TestClient
from pathlib import Path
import json

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


def test_health_exposes_llm_mode_without_exposing_api_key(tmp_path):
    settings = Settings(
        data_dir=tmp_path, database_path=tmp_path / "health.db", raw_archive_dir=tmp_path / "raw",
        neo4j_enabled=False, llm_base_url="https://model.example/v1", llm_api_key="never-return-this",
        llm_model="model-1", llm_timeout_seconds=180,
    )
    payload = TestClient(create_app(settings)).get("/api/system/health").json()["data"]
    assert payload["llm"] == {"configured": True, "execution_mode": "real_llm", "model": "model-1", "timeout_seconds": 180.0}
    assert "never-return-this" not in json.dumps(payload)


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
        attribution = client.get("/api/attribution").json()["data"]
        assert attribution[0]["status"] == "candidate_analysis"
        assert {"group", "confidence", "matched_features"} <= set(attribution[0])
        reports = client.get("/api/reports").json()["data"]
        assert {item["format"] for item in reports} == {"markdown", "html"}
        assert client.get(reports[0]["export_url"]).status_code == 200


def test_quick_investigation_uses_existing_route_and_four_agent_scope(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "api-quick.db", raw_archive_dir=tmp_path / "raw", report_dir=tmp_path / "reports", neo4j_enabled=False, llm_base_url="", llm_api_key="", llm_model="")
    app = create_app(settings)
    chain = build_pipeline(settings, app.state.repository, app.state.graph).run("run_api_quick", load_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain")).chains[0]
    with TestClient(app) as client:
        started = client.post("/api/chains/%s/investigate?scope=quick&max_steps=4" % chain.chain_id)
        assert started.status_code == 200
        assert started.json()["data"]["scope"] == "quick"
        detail = client.get("/api/agents/%s" % started.json()["data"]["case_id"]).json()["data"]
        assert [item["agent_role"] for item in detail["tasks"]] == ["coordinator", "host", "network", "correlation"]
        assert all(item["scope"] == "quick" for item in detail["tasks"])
