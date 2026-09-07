from typing import Dict, List

from app.contracts import Session, UnifiedSecurityEvent
from app.core.ids import stable_id


class Sessionizer:
    version = "1.0.0"

    def build(self, events: List[UnifiedSecurityEvent]) -> List[Session]:
        sessions: Dict[str, Session] = {}
        for event in sorted(events, key=lambda item: item.event_time):
            if event.action in {"auth.logon", "auth.logoff"} and event.object.ref and event.object.ref.entity_type == "session":
                session_id = event.object.ref.entity_id
                existing = sessions.get(session_id)
                if event.action == "auth.logon":
                    sessions[session_id] = Session(
                        session_id=session_id, session_type="login", start_time=event.event_time,
                        state="active", host_id=event.host.entity_id if event.host else None,
                        user_id=event.actor.user.entity_id if event.actor.user else None,
                        src_ip=event.object.ref.attributes.get("ip_address"), source_event_ids=[event.event_id],
                        confidence=1.0 if event.outcome == "success" else 0.5,
                    )
                elif existing:
                    existing.end_time = event.event_time
                    existing.state = "closed"
                    existing.source_event_ids.append(event.event_id)
                else:
                    sessions[session_id] = Session(
                        session_id=session_id, session_type="login", start_time=event.event_time,
                        end_time=event.event_time, state="orphan_end",
                        host_id=event.host.entity_id if event.host else None,
                        user_id=event.actor.user.entity_id if event.actor.user else None,
                        source_event_ids=[event.event_id], confidence=0.5,
                    )
            if event.network:
                session_id = event.network.session_id or stable_id(
                    "session", event.source.sensor_id, event.network.src.ip, event.network.src.port,
                    event.network.dst.ip, event.network.dst.port, int(event.event_time.timestamp()),
                )
                event.network.session_id = session_id
                existing = sessions.get(session_id)
                if existing:
                    existing.source_event_ids = sorted(set(existing.source_event_ids + [event.event_id]))
                    existing.end_time = max(existing.end_time or existing.start_time, event.event_time)
                else:
                    sessions[session_id] = Session(
                        session_id=session_id, session_type="network", start_time=event.event_time,
                        end_time=event.event_time if event.action == "network.flow" else None,
                        state="closed" if event.action == "network.flow" else "active",
                        host_id=event.host.entity_id if event.host else None,
                        src_ip=event.network.src.ip, dst_ip=event.network.dst.ip,
                        protocol=event.network.transport, source_event_ids=[event.event_id],
                        confidence=1.0 if event.network.zeek_uid else 0.8,
                    )
        return list(sessions.values())

