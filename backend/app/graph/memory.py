from typing import Dict

from app.contracts import GraphEntity, GraphRelation
from app.entities import GraphProjectionBatch


class InMemoryGraphProjector:
    """Deterministic projector used for tests and when Neo4j is unavailable."""

    def __init__(self) -> None:
        self.entities: Dict[str, GraphEntity] = {}
        self.relations: Dict[str, GraphRelation] = {}

    def project(self, batch: GraphProjectionBatch) -> int:
        before = len(self.entities) + len(self.relations)
        self.entities.update({entity.entity_id: entity for entity in batch.entities})
        self.relations.update({relation.relation_id: relation for relation in batch.relations})
        return len(self.entities) + len(self.relations) - before

