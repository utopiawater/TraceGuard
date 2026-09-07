from typing import Protocol

from app.entities import GraphProjectionBatch


class GraphProjector(Protocol):
    def project(self, batch: GraphProjectionBatch) -> int: ...

