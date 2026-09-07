from pathlib import Path
from typing import Any, Dict

from app.entities import GraphProjectionBatch


LABELS: Dict[str, str] = {
    "host": "Host", "user": "User", "process": "Process", "file": "File",
    "registry": "Registry", "ip": "IP", "domain": "Domain", "session": "Session",
    "alert": "Alert", "technique": "Technique", "c2": "C2", "evidence": "Evidence",
}
RELATIONS = {"HAS_IP", "SPAWNED", "EXECUTED_BY", "LOGGED_IN", "ON_HOST", "ACCESSED", "CREATED", "MODIFIED", "DELETED", "INITIATED", "FROM", "TO", "COMMUNICATED_WITH", "RESOLVED_TO", "TRIGGERED", "USED_TECHNIQUE", "HOSTED_AT", "USES_DOMAIN", "SUPPORTED_BY", "CORROBORATES"}


class Neo4jProjector:
    """Idempotent Neo4j projection; labels and relationship types are allowlisted."""

    def __init__(self, driver: Any) -> None:
        self.driver = driver

    def apply_schema(self, path: Path) -> None:
        statements = [item.strip() for item in Path(path).read_text(encoding="utf-8").split(";") if item.strip()]
        with self.driver.session() as session:
            for statement in statements:
                session.run(statement).consume()

    def project(self, batch: GraphProjectionBatch) -> int:
        with self.driver.session() as session:
            for entity in batch.entities:
                label = LABELS[entity.entity_type]
                session.run(
                    "MERGE (n:%s {entity_id: $entity_id}) SET n += $properties, n.display_name=$display_name, n.first_seen=$first_seen, n.last_seen=$last_seen, n.identity_quality=$identity_quality, n.evidence_ids=$evidence_ids" % label,
                    entity_id=entity.entity_id, properties=entity.properties, display_name=entity.display_name,
                    first_seen=entity.first_seen.isoformat() if entity.first_seen else None, last_seen=entity.last_seen.isoformat() if entity.last_seen else None, identity_quality=entity.identity_quality,
                    evidence_ids=entity.evidence_ids,
                )
            for relation in batch.relations:
                if relation.relation_type not in RELATIONS:
                    raise ValueError("relationship type is not allowlisted")
                session.run(
                    "MATCH (a {entity_id:$source}), (b {entity_id:$target}) MERGE (a)-[r:%s {relation_id:$relation_id}]->(b) SET r += $properties, r.start_time=$start_time, r.end_time=$end_time, r.confidence=$confidence, r.derived=$derived, r.event_ids=$event_ids, r.evidence_ids=$evidence_ids" % relation.relation_type,
                    source=relation.source_entity_id, target=relation.target_entity_id, relation_id=relation.relation_id,
                    properties=relation.properties, start_time=relation.start_time.isoformat() if relation.start_time else None, end_time=relation.end_time.isoformat() if relation.end_time else None,
                    confidence=relation.confidence, derived=relation.derived, event_ids=relation.event_ids, evidence_ids=relation.evidence_ids,
                )
        return len(batch.entities) + len(batch.relations)
