from typing import List, Protocol

from app.contracts import RawEventEnvelope, UnifiedSecurityEvent


class AdapterError(ValueError):
    pass


class Normalizer(Protocol):
    name: str
    version: str

    def supports(self, raw: RawEventEnvelope) -> bool: ...
    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]: ...

