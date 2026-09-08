import json
import threading
from typing import Any, Dict

import httpx
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class ModelUnavailableError(RuntimeError):
    pass


class OpenAICompatibleModelClient:
    """Provider-neutral chat-completions client with strict JSON Schema output."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: float = 180) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._response_format = "json_schema"
        self._local = threading.local()

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def complete_json(self, role: str, prompt_version: str, payload: dict, schema: dict) -> dict:
        if not self.configured:
            raise ModelUnavailableError("LLM_BASE_URL, LLM_API_KEY and LLM_MODEL are not fully configured")
        last_error: Exception = ModelUnavailableError("model response was not attempted")
        for attempt in range(2):
            try:
                value = self._request(role, prompt_version, payload, schema, attempt)
                Draft202012Validator(schema).validate(value)
                return value
            except (json.JSONDecodeError, JsonSchemaValidationError, TypeError, KeyError, ValueError) as exc:
                last_error = exc
        raise ModelUnavailableError("model JSON could not be parsed after one retry: %s" % last_error)

    def last_usage(self) -> Dict[str, int]:
        return dict(getattr(self._local, "usage", {}))

    def _request(self, role: str, prompt_version: str, payload: dict, schema: dict, attempt: int) -> Dict[str, Any]:
        system = (
            "You are the TraceGuard %s agent. Return only the requested JSON object. "
            "Never invent event, detection, entity, evidence, chain, or ATT&CK identifiers. "
            "Every factual finding must cite one or more evidence_ids from the supplied context. "
            "Do not reveal chain-of-thought; return concise structured findings only. Prompt version: %s."
        ) % (role, prompt_version)
        if self._response_format == "json_object":
            system += " Your response must validate against this exact JSON Schema: %s" % json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
        if attempt:
            system += " The prior response failed JSON parsing or schema validation; correct it and strictly conform to the schema."
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
            ],
            "response_format": self._format(schema),
        }
        try:
            response = httpx.post(
                "%s/chat/completions" % self.base_url,
                headers={"Authorization": "Bearer %s" % self.api_key, "Content-Type": "application/json"},
                json=body,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.lower()
            if exc.response.status_code == 400 and self._response_format == "json_schema" and "response_format" in detail and "unavailable" in detail:
                self._response_format = "json_object"
                return self._request(role, prompt_version, payload, schema, attempt)
            raise ModelUnavailableError("model request failed with HTTP %s" % exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            raise ModelUnavailableError("model request failed: %s" % exc) from exc
        response_payload = response.json()
        usage = response_payload.get("usage") or {}
        self._local.usage = {key: int(value) for key, value in usage.items() if key in {"prompt_tokens", "completion_tokens", "total_tokens"} and isinstance(value, (int, float))}
        content = response_payload["choices"][0]["message"]["content"]
        if isinstance(content, dict):
            return content
        return json.loads(content)

    def _format(self, schema: dict) -> dict:
        if self._response_format == "json_object":
            return {"type": "json_object"}
        return {"type": "json_schema", "json_schema": {"name": "traceguard_agent_result", "strict": True, "schema": schema}}
