import json
from pathlib import Path
from typing import Dict, Type

from pydantic import BaseModel

from . import AgentResult, AgentTask, Alert, AttackChain, DetectionResult, Evidence, GraphEntity, GraphRelation, RawEventEnvelope, Session, UnifiedSecurityEvent

MODELS = [RawEventEnvelope, UnifiedSecurityEvent, Session, DetectionResult, Evidence, GraphEntity, GraphRelation, Alert, AttackChain, AgentTask, AgentResult]


def publish_json_schemas(target: Path) -> Dict[str, Path]:
    target.mkdir(parents=True, exist_ok=True)
    written = {}
    for model in MODELS:
        path = target / (model.__name__ + ".schema.json")
        path.write_text(json.dumps(model.model_json_schema(), indent=2, ensure_ascii=False), encoding="utf-8")
        written[model.__name__] = path
    return written

