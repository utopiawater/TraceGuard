import json
import sys
from pathlib import Path
from pydantic.json_schema import models_json_schema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.contracts import AgentResult, AgentTask, Alert, AttackChain, DetectionResult, Evidence, GraphEntity, GraphRelation, RawEventEnvelope, Session, UnifiedSecurityEvent


if __name__ == "__main__":
    models = [RawEventEnvelope, UnifiedSecurityEvent, Session, DetectionResult, Evidence, GraphEntity, GraphRelation, Alert, AttackChain, AgentTask, AgentResult]
    _, combined = models_json_schema([(model, "validation") for model in models], ref_template="#/components/schemas/{model}")
    document = {
        "openapi": "3.1.0",
        "info": {"title": "TraceGuard Contract API", "version": "0.1.0"},
        "paths": {},
        "components": {"schemas": combined["$defs"]},
    }
    target = ROOT / "artifacts" / "openapi.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    print(target)
