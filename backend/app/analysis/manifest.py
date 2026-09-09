import json
from pathlib import Path
from typing import Any


POLICY_KEYS = ("default_timezone", "asset_aliases", "sensitive_path_patterns")
GT_KEYS = {
    "attack_steps",
    "expected_technique",
    "expected_techniques",
    "ground_truth",
    "gt",
    "labels",
    "dataset_label",
    "scenario_answer",
    "expected_attack",
    "known_attacker",
}


def _scalar(value: str) -> Any:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return None
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            import ast

            return ast.literal_eval(stripped)
        except Exception:
            return stripped
    return stripped


def _read_simple_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    section: str | None = None
    current_node: dict[str, Any] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith(" "):
            key, _, value = raw_line.partition(":")
            section = key.strip()
            current_node = None
            if value.strip():
                data[section] = _scalar(value)
            elif section == "nodes":
                data.setdefault("nodes", [])
            elif section in {"asset_aliases"}:
                data.setdefault(section, {})
            elif section in {"sensitive_path_patterns"}:
                data.setdefault(section, [])
            else:
                data.setdefault(section, None)
            continue
        if section is None:
            continue
        stripped = raw_line.strip()
        if section == "nodes" and stripped.startswith("- "):
            current_node = {}
            data.setdefault("nodes", []).append(current_node)
            stripped = stripped[2:].strip()
            if stripped:
                key, _, value = stripped.partition(":")
                current_node[key.strip()] = _scalar(value)
        elif section == "nodes" and current_node is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current_node[key.strip()] = _scalar(value)
        elif section == "asset_aliases" and ":" in stripped:
            key, _, value = stripped.partition(":")
            data.setdefault(section, {})[key.strip()] = _scalar(value)
        elif section == "sensitive_path_patterns" and stripped.startswith("- "):
            data.setdefault(section, []).append(_scalar(stripped[2:]))
    return data


def read_manifest_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"missing": True, "nodes": []}
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return _read_simple_yaml(path)


def environment_policy(manifest: dict[str, Any]) -> dict[str, Any]:
    policy = {key: manifest[key] for key in POLICY_KEYS if key in manifest}
    if "default_timezone" not in policy and manifest.get("timezone"):
        policy["default_timezone"] = manifest["timezone"]
    aliases = _asset_alias_policy(manifest)
    if aliases:
        policy["asset_aliases"] = aliases
    return policy


def _asset_alias_policy(manifest: dict[str, Any]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    configured = manifest.get("asset_aliases")
    if isinstance(configured, dict):
        aliases.update({str(alias): str(canonical) for alias, canonical in configured.items() if str(alias).strip() and str(canonical).strip()})
    nodes = manifest.get("nodes")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            canonical = node.get("asset_id") or node.get("canonical_asset") or node.get("hostname") or node.get("node_id")
            if not canonical:
                continue
            candidates = [node.get("node_id"), node.get("hostname"), node.get("name"), node.get("role")]
            for field in ("aliases", "ips", "ip_addresses", "sensors", "path_aliases"):
                value = node.get(field)
                if isinstance(value, list):
                    candidates.extend(value)
                elif value:
                    candidates.append(value)
            for candidate in candidates:
                if candidate:
                    aliases.setdefault(str(candidate), str(canonical))
    return aliases
