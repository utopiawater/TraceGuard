"""Extension point retained for public dataset adapters planned for the next phase."""
from typing import List

from app.contracts import RawEventEnvelope, UnifiedSecurityEvent
from app.contracts.common import SourceKind

from .base import AdapterError


class _PendingAdapter:
    source_kind: SourceKind
    name = "pending"
    version = "1.0.0"

    def supports(self, raw: RawEventEnvelope) -> bool:
        return raw.source.kind == self.source_kind

    def normalize(self, raw: RawEventEnvelope) -> List[UnifiedSecurityEvent]:
        raise AdapterError("%s is registered but its source parser is not available" % self.name)


class DatasetAdapter(_PendingAdapter):
    source_kind = SourceKind.dataset
    name = "dataset"


from .auditd import AuditdAdapter  # compatibility import
from .wazuh import WazuhAdapter  # compatibility import
