from typing import List

from app.attribution.fingerprint import AttackFingerprint
from app.contracts.base import ContractModel


class C2Profile(ContractModel):
    domain: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    user_agent: str | None = None
    domain_age: str | None = None
    asn: str | None = None
    related_domains: List[str] = []
    historical_ip: List[str] = []
    tls_fingerprint: str | None = None


MOCK_C2_DB = {
    "203.0.113.77": {
        "asn": "AS64512 LAB-NET",
        "historical_ip": ["198.51.100.24", "203.0.113.77"],
        "related_domains": ["beacon.backup-sync.example", "cdn-status.example"],
        "tls_fingerprint": "ja3:72a589da586844d7f0818ce684948eea",
    },
    "beacon.backup-sync.example": {
        "domain_age": "12 days",
        "asn": "AS64512 LAB-NET",
        "historical_ip": ["203.0.113.77"],
        "related_domains": ["api.backup-sync.example", "cdn-status.example"],
        "tls_fingerprint": "ja3:72a589da586844d7f0818ce684948eea",
    },
}


def analyze_c2(fingerprint: AttackFingerprint, port: int | None = None, protocol: str | None = None) -> List[C2Profile]:
    profiles: List[C2Profile] = []
    indicators = [(domain, None) for domain in fingerprint.domain] + [(None, ip) for ip in fingerprint.ip]
    for domain, ip in indicators:
        key = domain or ip or ""
        mock = MOCK_C2_DB.get(key, {})
        profiles.append(C2Profile(
            domain=domain,
            ip=ip,
            port=port or (443 if fingerprint.user_agent or protocol == "https" else None),
            protocol=protocol or ("https" if fingerprint.user_agent else None),
            user_agent=fingerprint.user_agent[0] if fingerprint.user_agent else None,
            domain_age=mock.get("domain_age"),
            asn=mock.get("asn"),
            related_domains=mock.get("related_domains", []),
            historical_ip=mock.get("historical_ip", []),
            tls_fingerprint=mock.get("tls_fingerprint"),
        ))
    return profiles
