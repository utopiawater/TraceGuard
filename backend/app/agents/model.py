import json
from typing import Any, Dict

import httpx


class ModelUnavailableError(RuntimeError):
    pass


class OpenAICompatibleModelClient:
    """Provider-neutral chat-completions client with strict JSON Schema output."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: float = 45) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def complete_json(self, role: str, prompt_version: str, payload: dict, schema: dict) -> dict:
        if not self.configured:
            raise ModelUnavailableError("LLM_BASE_URL, LLM_API_KEY and LLM_MODEL are not fully configured")
        last_error: Exception = ModelUnavailableError("model response was not attempted")
        for attempt in range(2):
            try:
                return self._request(role, prompt_version, payload, schema, attempt)
            except (json.JSONDecodeError, TypeError, KeyError, ValueError) as exc:
                last_error = exc
        raise ModelUnavailableError("model JSON could not be parsed after one retry: %s" % last_error)

    def _request(self, role: str, prompt_version: str, payload: dict, schema: dict, attempt: int) -> Dict[str, Any]:
        system = (
            "You are the TraceGuard %s agent. Return only the requested JSON object. "
            "Never invent event, detection, entity, evidence, chain, or ATT&CK identifiers. "
            "Every factual finding must cite one or more evidence_ids from the supplied context. "
            "Do not reveal chain-of-thought; return concise structured findings only. Prompt version: %s."
        ) % (role, prompt_version)
        if attempt:
            system += " The prior response was invalid JSON; strictly conform to the schema."
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "traceguard_agent_result", "strict": True, "schema": schema},
            },
        }
        try:
            response = httpx.post(
                "%s/chat/completions" % self.base_url,
                headers={"Authorization": "Bearer %s" % self.api_key, "Content-Type": "application/json"},
                json=body,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelUnavailableError("model request failed: %s" % exc) from exc
        content = response.json()["choices"][0]["message"]["content"]
        if isinstance(content, dict):
            return content
        return json.loads(content)

