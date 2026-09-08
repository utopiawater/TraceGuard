from typing import Any, Dict, List

from app.attribution.c2_analysis import C2Profile
from app.attribution.fingerprint import AttackFingerprint


def rank_groups(fingerprint: AttackFingerprint, c2_profiles: List[C2Profile], groups: List[dict]) -> List[Dict[str, Any]]:
    candidates = []
    c2_terms = _c2_terms(fingerprint, c2_profiles)
    for group in groups:
        techniques = set(group.get("techniques") or group.get("technique_ids") or [])
        tools = {item.lower() for item in group.get("tools", [])}
        malware = {item.lower() for item in group.get("malware", [])}
        c2_features = {item.lower() for item in group.get("c2_features", [])}

        technique_matches = sorted(set(fingerprint.techniques) & techniques)
        tool_matches = sorted({tool for tool in tools if _contains_any(tool, fingerprint.process_name + fingerprint.command_pattern + fingerprint.user_agent)})
        malware_matches = sorted({item for item in malware if _contains_any(item, fingerprint.file_hash + fingerprint.command_pattern)})
        c2_matches = sorted({feature for feature in c2_features if _contains_any(feature, c2_terms)})
        matched_features = (
            ["technique:%s" % item for item in technique_matches]
            + ["tool:%s" % item for item in tool_matches]
            + ["malware:%s" % item for item in malware_matches]
            + ["c2:%s" % item for item in c2_matches]
        )

        technique_score = len(technique_matches) / max(len(set(fingerprint.techniques) | techniques), 1)
        tool_score = min(len(tool_matches) * 0.12, 0.24)
        malware_score = min(len(malware_matches) * 0.16, 0.24)
        c2_score = min(len(c2_matches) * 0.08, 0.24)
        confidence = min(0.94, round(0.52 * technique_score + tool_score + malware_score + c2_score, 4))
        candidates.append({
            "group": group["name"],
            "group_id": group.get("group_id"),
            "confidence": confidence,
            "matched_features": matched_features,
            "technique_overlap": technique_matches,
            "tools": sorted(tool_matches),
            "malware": sorted(malware_matches),
            "c2_features": sorted(c2_matches),
        })
    return sorted(candidates, key=lambda item: (item["confidence"], len(item["matched_features"])), reverse=True)[:3]


def _contains_any(needle: str, haystack: List[str]) -> bool:
    normalized = needle.replace("_", "-").lower()
    variants = {normalized, normalized.replace("-", "_"), normalized.replace("-", "")}
    return any(any(variant in item.lower().replace(" ", "-") for variant in variants) for item in haystack)


def _c2_terms(fingerprint: AttackFingerprint, profiles: List[C2Profile]) -> List[str]:
    values = fingerprint.domain + fingerprint.ip + fingerprint.user_agent
    for profile in profiles:
        values.extend([
            profile.protocol,
            profile.user_agent,
            profile.asn,
            profile.tls_fingerprint,
            profile.domain_age,
            "short_lived_domain" if profile.domain_age else None,
        ])
        values.extend(profile.related_domains)
        values.extend(profile.historical_ip)
    return [value for value in values if value]
