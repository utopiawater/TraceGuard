from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable, List

from app.contracts import RawEventEnvelope


@dataclass(frozen=True)
class CollectorStatus:
    name: str
    status: str
    event_count: int
    detail: str | None = None


class BaseCollector(ABC):
    name: str

    @abstractmethod
    def collect(self) -> List[RawEventEnvelope]:
        """Read a source and return raw TraceGuard envelopes."""

    @abstractmethod
    def parse(self, record: Any) -> RawEventEnvelope:
        """Convert one source-specific record into RawEventEnvelope."""

    def health_check(self) -> CollectorStatus:
        try:
            return CollectorStatus(name=self.name, status="ok", event_count=len(self.collect()))
        except FileNotFoundError as exc:
            return CollectorStatus(name=self.name, status="missing_source", event_count=0, detail=str(exc))
        except Exception as exc:
            return CollectorStatus(name=self.name, status="error", event_count=0, detail=str(exc))


def non_empty_lines(lines: Iterable[str]) -> List[str]:
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
