from typing import Iterable, List

from app.contracts import RawEventEnvelope, UnifiedSecurityEvent

from .base import AdapterError, Normalizer


class NormalizerRegistry:
    def __init__(self, adapters: Iterable[Normalizer]) -> None:
        self.adapters = list(adapters)

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        matches = [adapter for adapter in self.adapters if adapter.supports(raw)]
        if not matches:
            raise AdapterError("no adapter registered for %s/%s" % (raw.source.kind.value, raw.source.dataset))
        return matches[0].normalize(raw)

