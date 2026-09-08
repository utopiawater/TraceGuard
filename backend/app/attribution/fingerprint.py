import re
from typing import Any, Iterable, List

from app.contracts import AttackChain, UnifiedSecurityEvent
from app.contracts.base import ContractModel
from app.repositories import SQLiteRepository


class AttackFingerprint(ContractModel):
    process_name: List[str] = []
    command_pattern: List[str] = []
    file_hash: List[str] = []
    domain: List[str] = []
    ip: List[str] = []
    user_agent: List[str] = []
    techniques: List[str] = []

    @classmethod
    def from_chain(cls, chain: AttackChain, repo: SQLiteRepository) -> "AttackFingerprint":
        event_ids = [event_id for step in chain.steps for event_id in step.event_ids]
        events = [event for event_id in event_ids if (event := repo.get_event(event_id))]
        return cls(
            process_name=_sorted(_process_names(events)),
            command_pattern=_sorted(_command_patterns(events)),
            file_hash=_sorted(_file_hashes(events)),
            domain=_sorted(_domains(events)),
            ip=_sorted(_ips(events)),
            user_agent=_sorted(_user_agents(events)),
            techniques=sorted(set(chain.technique_ids)),
        )


def _sorted(values: Iterable[str | None]) -> List[str]:
    return sorted({str(value).strip() for value in values if value and str(value).strip()})


def _process_names(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str | None]:
    for event in events:
        for ref in (event.actor.process, event.actor.parent_process):
            if ref:
                yield ref.display_name or ref.attributes.get("image")


def _command_patterns(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str]:
    for event in events:
        text = " ".join([event.message or "", str(event.extensions)])
        lower = text.lower()
        if "powershell" in lower:
            yield "powershell"
        if "-encodedcommand" in lower or "encodedcommand" in lower:
            yield "encoded_powershell"
        if "cmd.exe" in lower:
            yield "cmd_shell"
        if "curl" in lower:
            yield "curl_transfer"
        if "whoami" in lower:
            yield "discovery_whoami"


def _file_hashes(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str]:
    hash_re = re.compile(r"(?:SHA256|sha256)=([A-Fa-f0-9]{32,64})")
    for event in events:
        for match in hash_re.findall(str(event.extensions)):
            yield match.lower()


def _domains(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str | None]:
    for event in events:
        if event.network and event.network.dns:
            query = event.network.dns.get("query")
            if query:
                yield str(query).lower()
        ref = event.object.ref
        if ref and ref.entity_type == "domain":
            yield ref.display_name


def _ips(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str | None]:
    for event in events:
        if event.network:
            yield event.network.src.ip
            yield event.network.dst.ip


def _user_agents(events: Iterable[UnifiedSecurityEvent]) -> Iterable[str]:
    for event in events:
        values: list[Any] = []
        if event.network and event.network.http:
            values.extend([event.network.http.get("user_agent"), event.network.http.get("user-agent")])
        values.append(event.extensions)
        text = str(values)
        for token in ("curl", "powershell", "python-requests", "Mozilla"):
            if token.lower() in text.lower():
                yield token
