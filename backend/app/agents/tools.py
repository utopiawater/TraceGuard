from collections import deque
from typing import List, Literal, Optional

from pydantic import Field, model_validator

from app.agents.harness import Tool, ToolGateway
from app.contracts.base import ContractModel
from app.knowledge import MappingFileProvider
from app.repositories import SQLiteRepository


class EventSearchArgs(ContractModel):
    run_id: Optional[str] = None
    actions: List[str] = Field(default_factory=list, max_length=20)
    source_kinds: List[str] = Field(default_factory=list, max_length=10)
    host_id: Optional[str] = None
    entity_id: Optional[str] = None
    text: Optional[str] = Field(default=None, max_length=160)
    limit: int = Field(default=50, ge=1, le=200)


class EntityTimelineArgs(ContractModel):
    run_id: Optional[str] = None
    entity_id: str = Field(min_length=1, max_length=200)
    limit: int = Field(default=100, ge=1, le=200)


class SessionLookupArgs(ContractModel):
    run_id: Optional[str] = None
    session_id: Optional[str] = None
    host_id: Optional[str] = None
    ip: Optional[str] = None
    session_type: Optional[Literal["login", "network"]] = None
    limit: int = Field(default=50, ge=1, le=100)

    @model_validator(mode="after")
    def require_selector(self):
        if not (self.session_id or self.host_id or self.ip or self.session_type):
            raise ValueError("at least one session selector is required")
        return self


class GraphNeighborsArgs(ContractModel):
    run_id: Optional[str] = None
    entity_id: str = Field(min_length=1, max_length=200)
    depth: int = Field(default=1, ge=1, le=3)
    limit: int = Field(default=50, ge=1, le=100)


class GraphPathArgs(ContractModel):
    run_id: Optional[str] = None
    source_entity_id: str = Field(min_length=1, max_length=200)
    target_entity_id: str = Field(min_length=1, max_length=200)
    max_depth: int = Field(default=4, ge=1, le=6)
    max_edges: int = Field(default=3000, ge=100, le=10000)


class IdsArgs(ContractModel):
    run_id: Optional[str] = None
    ids: List[str] = Field(min_length=1, max_length=50)


class ChainLookupArgs(ContractModel):
    chain_id: str = Field(min_length=1, max_length=200)


class AttackLookupArgs(ContractModel):
    technique_ids: List[str] = Field(min_length=1, max_length=20)


class ChainValidateArgs(ContractModel):
    chain_id: str = Field(min_length=1, max_length=200)


class SourceHealthArgs(ContractModel):
    run_id: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=100)


def _event_has_entity(event, entity_id: str) -> bool:
    refs = [event.host, event.actor.user, event.actor.process, event.actor.parent_process, event.object.ref]
    if any(ref and ref.entity_id == entity_id for ref in refs):
        return True
    if event.network:
        return entity_id in {
            event.network.src.host_id, event.network.src.ip, event.network.dst.host_id, event.network.dst.ip,
            event.network.session_id,
        }
    return False


def build_tool_gateway(repo: SQLiteRepository, graph, attack: MappingFileProvider) -> ToolGateway:
    run_event_cache = {}
    def event_search(args: dict) -> dict:
        rows = repo.query_events(
            run_id=args.get("run_id"),
            actions=args.get("actions") or None,
            source_kinds=args.get("source_kinds") or None,
            host_id=args.get("host_id"),
            entity_id=args.get("entity_id"),
            text=args.get("text"),
            limit=args["limit"] + 1,
        )
        values = [event.model_dump(mode="json") for event in rows[:args["limit"]]]
        return {"events": values, "count": len(values), "truncated": len(rows) > args["limit"]}

    def entity_timeline(args: dict) -> dict:
        events = repo.query_events(run_id=args.get("run_id"), entity_id=args["entity_id"], limit=args["limit"] + 1)
        return {"entity_id": args["entity_id"], "events": [item.model_dump(mode="json") for item in events[:args["limit"]]], "truncated": len(events) > args["limit"]}

    def session_lookup(args: dict) -> dict:
        rows = repo.query_sessions(
            run_id=args.get("run_id"),
            session_id=args.get("session_id"),
            host_id=args.get("host_id"),
            ip=args.get("ip"),
            session_type=args.get("session_type"),
            limit=args["limit"] + 1,
        )
        values = [session.model_dump(mode="json") for session in rows[:args["limit"]]]
        return {"sessions": values, "count": len(values), "truncated": len(rows) > args["limit"]}

    def _relation_in_scope(relation, run_id: Optional[str]) -> bool:
        if not run_id:
            return True
        event_ids = run_event_cache.setdefault(run_id, set(repo.event_ids_for_run(run_id)))
        return bool(set(relation.event_ids) & event_ids)

    def graph_neighbors(args: dict) -> dict:
        root, max_depth, limit = args["entity_id"], args["depth"], args["limit"]
        seen, frontier, edges = {root}, {root}, []
        for _ in range(max_depth):
            next_frontier = set()
            for relation in graph.relations.values():
                if not _relation_in_scope(relation, args.get("run_id")):
                    continue
                if relation.source_entity_id in frontier or relation.target_entity_id in frontier:
                    edges.append(relation)
                    next_frontier.update([relation.source_entity_id, relation.target_entity_id])
                    if len(edges) >= limit:
                        break
            frontier = next_frontier - seen
            seen.update(next_frontier)
            if not frontier or len(edges) >= limit:
                break
        entities = [graph.entities[item].model_dump(mode="json") for item in seen if item in graph.entities]
        return {"root_entity_id": root, "depth": max_depth, "nodes": entities[:limit], "edges": [item.model_dump(mode="json") for item in edges[:limit]], "truncated": len(edges) >= limit}

    def graph_path(args: dict) -> dict:
        source, target, max_depth, max_edges = args["source_entity_id"], args["target_entity_id"], args["max_depth"], args["max_edges"]
        adjacency = {}
        considered = 0
        for relation in graph.relations.values():
            if not _relation_in_scope(relation, args.get("run_id")):
                continue
            considered += 1
            if considered > max_edges:
                break
            adjacency.setdefault(relation.source_entity_id, []).append((relation.target_entity_id, relation))
            adjacency.setdefault(relation.target_entity_id, []).append((relation.source_entity_id, relation))
        queue = deque([(source, [source], [])])
        seen = {source}
        while queue:
            current, nodes, relations = queue.popleft()
            if current == target:
                return {"found": True, "node_ids": nodes, "relations": [item.model_dump(mode="json") for item in relations], "depth": len(relations)}
            if len(relations) >= max_depth:
                continue
            for neighbor, relation in adjacency.get(current, []):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, nodes + [neighbor], relations + [relation]))
        return {"found": False, "node_ids": [], "relations": [], "depth": None, "truncated": considered > max_edges}

    def detection_lookup(args: dict) -> dict:
        values = []
        for detection_id in args["ids"]:
            item = repo.get_detection(detection_id)
            if not item:
                raise ValueError("detection does not exist: %s" % detection_id)
            if args.get("run_id") and item.run_id != args["run_id"]:
                raise ValueError("detection is outside requested run: %s" % detection_id)
            values.append(item.model_dump(mode="json"))
        return {"detections": values}

    def chain_lookup(args: dict) -> dict:
        item = repo.get_chain(args["chain_id"])
        if not item:
            raise ValueError("attack chain does not exist: %s" % args["chain_id"])
        return {"chain": item.model_dump(mode="json")}

    def attack_lookup(args: dict) -> dict:
        values = []
        for technique_id in args["technique_ids"]:
            item = attack.technique(technique_id)
            if item.get("name") == "Unknown":
                raise ValueError("ATT&CK technique does not exist in pinned knowledge: %s" % technique_id)
            values.append(item)
        return {"attack_version": attack.version, "techniques": values, "groups": attack.groups()[:20], "software": attack.software()[:20]}

    def evidence_get(args: dict) -> dict:
        values = []
        for evidence_id in args["ids"]:
            item = repo.get_evidence(evidence_id)
            if not item:
                raise ValueError("evidence does not exist: %s" % evidence_id)
            if args.get("run_id") and repo.get_evidence_run_id(evidence_id) != args["run_id"]:
                raise ValueError("evidence is outside requested run: %s" % evidence_id)
            values.append(item.model_dump(mode="json"))
        return {"evidence": values}

    def chain_validate(args: dict) -> dict:
        chain = repo.get_chain(args["chain_id"])
        if not chain:
            raise ValueError("attack chain does not exist: %s" % args["chain_id"])
        errors, prior_steps = [], set()
        for step in chain.steps:
            if step.start_time > step.end_time:
                errors.append("step %s has an invalid time range" % step.step_id)
            for event_id in step.event_ids:
                if not repo.get_event(event_id):
                    errors.append("step %s references missing event %s" % (step.step_id, event_id))
            for detection_id in step.detection_ids:
                if not repo.get_detection(detection_id):
                    errors.append("step %s references missing detection %s" % (step.step_id, detection_id))
            for evidence_id in step.evidence_ids:
                if not repo.get_evidence(evidence_id):
                    errors.append("step %s references missing evidence %s" % (step.step_id, evidence_id))
            for entity_id in step.entity_ids:
                if entity_id not in graph.entities:
                    errors.append("step %s references missing graph entity %s" % (step.step_id, entity_id))
            for session_id in step.session_ids:
                if not repo.get_session(session_id):
                    errors.append("step %s references missing session %s" % (step.step_id, session_id))
            for predecessor in step.predecessors:
                if predecessor.step_id not in prior_steps:
                    errors.append("step %s has a missing or forward predecessor %s" % (step.step_id, predecessor.step_id))
                for evidence_id in predecessor.evidence_ids:
                    if not repo.get_evidence(evidence_id):
                        errors.append("predecessor for %s references missing evidence %s" % (step.step_id, evidence_id))
            if attack.technique(step.technique_id).get("name") == "Unknown":
                errors.append("step %s references unknown ATT&CK technique %s" % (step.step_id, step.technique_id))
            prior_steps.add(step.step_id)
        return {"chain_id": chain.chain_id, "valid": not errors, "errors": errors, "step_ids": [step.step_id for step in chain.steps], "evidence_ids": chain.evidence_ids}

    def source_health(args: dict) -> dict:
        values = {}
        for event in repo.all_events(run_id=args.get("run_id")):
            values[event.source.sensor_id] = {
                "sensor_id": event.source.sensor_id, "kind": event.source.kind.value,
                "last_event_time": event.event_time.isoformat(), "status": "ingested",
            }
        return {"sources": list(values.values())[:args["limit"]], "graph_runtime": graph.status() if hasattr(graph, "status") else {"connected": False}}

    return ToolGateway([
        Tool("event_search", event_search, EventSearchArgs),
        Tool("entity_timeline", entity_timeline, EntityTimelineArgs),
        Tool("session_lookup", session_lookup, SessionLookupArgs),
        Tool("graph_neighbors", graph_neighbors, GraphNeighborsArgs),
        Tool("graph_path", graph_path, GraphPathArgs),
        Tool("detection_lookup", detection_lookup, IdsArgs),
        Tool("chain_lookup", chain_lookup, ChainLookupArgs),
        Tool("attack_lookup", attack_lookup, AttackLookupArgs),
        Tool("evidence_get", evidence_get, IdsArgs),
        Tool("chain_validate", chain_validate, ChainValidateArgs),
        Tool("source_health", source_health, SourceHealthArgs),
    ])
