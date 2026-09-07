from typing import List, Type

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from pydantic.json_schema import models_json_schema

from app.contracts import (
    AgentResult, AgentTask, Alert, AttackChain, DetectionResult, Evidence,
    GraphEntity, GraphRelation, RawEventEnvelope, Session, UnifiedSecurityEvent,
)


CONTRACT_MODELS: List[Type[BaseModel]] = [
    RawEventEnvelope, UnifiedSecurityEvent, Session, DetectionResult, Evidence,
    GraphEntity, GraphRelation, Alert, AttackChain, AgentTask, AgentResult,
]


def install_contract_openapi(app: FastAPI) -> None:
    """Publish boundary contracts even when resource envelopes are assembled dynamically."""

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        document = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
        _, combined = models_json_schema(
            [(model, "validation") for model in CONTRACT_MODELS],
            ref_template="#/components/schemas/{model}",
        )
        document.setdefault("components", {}).setdefault("schemas", {}).update(combined["$defs"])
        app.openapi_schema = document
        return document

    app.openapi = custom_openapi

