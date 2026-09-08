from typing import Dict, List, Optional

from pydantic import Field

from app.contracts import DetectionResult, GraphEntity, GraphRelation, Session, UnifiedSecurityEvent
from app.contracts.base import ContractModel
from app.core.ids import stable_id


class GraphProjectionBatch(ContractModel):
    entities: List[GraphEntity] = Field(default_factory=list)
    relations: List[GraphRelation] = Field(default_factory=list)


class EntityResolver:
    version = "1.0.0"
    max_entity_evidence = 200

    def resolve(
        self,
        events: List[UnifiedSecurityEvent],
        sessions: List[Session],
        detections: Optional[List[DetectionResult]] = None,
    ) -> GraphProjectionBatch:
        entities: Dict[str, GraphEntity] = {}
        relations: Dict[str, GraphRelation] = {}
        event_evidence = {event.event_id: stable_id("evd", event.event_id, "normalized") for event in events}

        def add_entity(ref, event: UnifiedSecurityEvent) -> None:
            if ref is None:
                return
            previous = entities.get(ref.entity_id)
            evidence_ids = sorted(set((previous.evidence_ids if previous else []) + [event_evidence[event.event_id]]))[:self.max_entity_evidence]
            entities[ref.entity_id] = GraphEntity(
                entity_id=ref.entity_id,
                entity_type=ref.entity_type,
                labels=[ref.entity_type.title()],
                display_name=ref.display_name,
                properties=ref.attributes,
                first_seen=previous.first_seen if previous else event.event_time,
                last_seen=event.event_time,
                identity_quality=ref.identity_quality,
                evidence_ids=evidence_ids,
            )

        def add_relation(kind: str, source: str, target: str, event: UnifiedSecurityEvent, confidence: float = 1.0, properties=None, derived: bool = False) -> None:
            relation_id = stable_id("rel", kind, source, target, event.event_id)
            relations[relation_id] = GraphRelation(
                relation_id=relation_id,
                relation_type=kind,
                source_entity_id=source,
                target_entity_id=target,
                start_time=event.event_time,
                properties=properties or {},
                confidence=confidence,
                derived=derived,
                event_ids=[event.event_id],
                evidence_ids=[event_evidence[event.event_id]],
            )

        for event in events:
            for ref in (event.host, event.actor.user, event.actor.process, event.actor.parent_process, event.object.ref):
                add_entity(ref, event)
            if event.actor.parent_process and event.actor.process:
                add_relation("SPAWNED", event.actor.parent_process.entity_id, event.actor.process.entity_id, event)
            if event.actor.process and event.actor.user:
                add_relation("EXECUTED_BY", event.actor.process.entity_id, event.actor.user.entity_id, event)
            if event.actor.process and event.host:
                add_relation("ON_HOST", event.actor.process.entity_id, event.host.entity_id, event)
            if event.object.ref and event.object.ref.entity_type == "session" and event.actor.user:
                add_relation("LOGGED_IN", event.actor.user.entity_id, event.object.ref.entity_id, event)
                if event.host:
                    add_relation("ON_HOST", event.object.ref.entity_id, event.host.entity_id, event)
            if event.network and event.network.session_id and event.actor.process:
                add_relation("INITIATED", event.actor.process.entity_id, event.network.session_id, event, 0.9)
            if event.actor.process and event.object.ref and event.object.ref.entity_type == "file":
                relation = {"file.create": "CREATED", "file.modify": "MODIFIED", "file.delete": "DELETED"}.get(event.action, "ACCESSED")
                add_relation(relation, event.actor.process.entity_id, event.object.ref.entity_id, event)
            if event.actor.process and event.object.ref and event.object.ref.entity_type == "registry":
                add_relation("MODIFIED", event.actor.process.entity_id, event.object.ref.entity_id, event)
            if event.network and event.network.session_id and event.object.ref and event.object.ref.entity_type in {"ip", "domain"}:
                add_relation("COMMUNICATED_WITH", event.network.session_id, event.object.ref.entity_id, event, 0.9)

        by_id = {event.event_id: event for event in events}
        for session in sessions:
            related = next((by_id[event_id] for event_id in session.source_event_ids if event_id in by_id), None)
            evidence_ids = [event_evidence[event_id] for event_id in session.source_event_ids if event_id in event_evidence]
            entities[session.session_id] = GraphEntity(
                entity_id=session.session_id,
                entity_type="session",
                labels=["Session"],
                display_name=session.session_id,
                properties={"type": session.session_type, "state": session.state, "confidence": session.confidence},
                first_seen=session.start_time,
                last_seen=session.end_time or session.start_time,
                identity_quality="exact" if session.confidence >= 0.9 else "derived",
                evidence_ids=evidence_ids,
            )
            if related and session.src_ip and session.dst_ip:
                for address, relation_type in ((session.src_ip, "FROM"), (session.dst_ip, "TO")):
                    ip_id = stable_id("ip", address)
                    entities.setdefault(ip_id, GraphEntity(
                        entity_id=ip_id,
                        entity_type="ip",
                        labels=["IP"],
                        display_name=address,
                        properties={"address": address},
                        first_seen=session.start_time,
                        last_seen=session.end_time or session.start_time,
                        identity_quality="exact",
                        evidence_ids=evidence_ids,
                    ))
                    add_relation(relation_type, session.session_id, ip_id, related, session.confidence)

        for detection in detections or []:
            alert_id = detection.detection_id
            entities[alert_id] = GraphEntity(
                entity_id=alert_id,
                entity_type="alert",
                labels=["Alert"],
                display_name=detection.title,
                properties={"rule_id": detection.rule_id, "severity": detection.severity, "confidence": detection.confidence},
                first_seen=detection.created_at,
                last_seen=detection.created_at,
                identity_quality="exact",
                evidence_ids=detection.evidence_ids,
            )
            trigger_event = next((by_id[event_id] for event_id in detection.event_ids if event_id in by_id), None)
            if trigger_event:
                for entity_id in detection.entity_ids[:3]:
                    add_relation("TRIGGERED", entity_id, alert_id, trigger_event, detection.confidence, {"detection_id": detection.detection_id}, True)
                for mapping in detection.attack_mappings:
                    technique_id = mapping.subtechnique_id or mapping.technique_id
                    entities.setdefault(technique_id, GraphEntity(
                        entity_id=technique_id,
                        entity_type="technique",
                        labels=["Technique"],
                        display_name=technique_id,
                        properties={"attack_version": mapping.attack_version},
                        identity_quality="exact",
                        evidence_ids=detection.evidence_ids,
                    ))
                    add_relation("USED_TECHNIQUE", alert_id, technique_id, trigger_event, mapping.confidence, {"mapping_rule_id": mapping.mapping_rule_id, "attack_version": mapping.attack_version}, True)
                for source, target in zip(detection.session_ids, detection.session_ids[1:]):
                    if source in entities and target in entities:
                        add_relation("CORROBORATES", source, target, trigger_event, detection.confidence, {"detection_id": detection.detection_id}, True)

        return GraphProjectionBatch(entities=list(entities.values()), relations=list(relations.values()))
