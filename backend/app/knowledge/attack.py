import json
from pathlib import Path
from typing import Dict, List, Protocol

from app.contracts import AttackMapping


class AttackKnowledgeProvider(Protocol):
    version: str
    def mappings(self) -> Dict[str, List[AttackMapping]]: ...
    def technique(self, technique_id: str) -> dict: ...


class MappingFileProvider:
    def __init__(self, path: Path) -> None:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        self.version = payload["attack_version"]
        self._techniques = payload.get("techniques", {})
        self._groups = payload.get("groups", {})
        self._software = payload.get("software", {})
        self._mappings = {
            rule_id: [AttackMapping.model_validate(item) for item in values]
            for rule_id, values in payload["mappings"].items()
        }

    def mappings(self) -> Dict[str, List[AttackMapping]]:
        return self._mappings

    def technique(self, technique_id: str) -> dict:
        return self._techniques.get(technique_id, {"technique_id": technique_id, "name": "Unknown", "attack_version": self.version})

    def groups(self) -> List[dict]:
        return [dict({"group_id": key}, **value) for key, value in self._groups.items()]

    def software(self) -> List[dict]:
        return [dict({"software_id": key}, **value) for key, value in self._software.items()]


class AttackMappingRegistry:
    def __init__(self, provider: AttackKnowledgeProvider) -> None:
        self.provider = provider

    def for_detection(self, rule_id: str) -> List[AttackMapping]:
        return [item.model_copy(deep=True) for item in self.provider.mappings().get(rule_id, [])]
