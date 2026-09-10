from typing import Callable, List, Optional

from pydantic import Field

from app.attack import DeterministicChainBuilder
from app.contracts import AttackChain, DetectionResult, Evidence, GraphEntity, GraphRelation, RawEventEnvelope, Session, UnifiedSecurityEvent
from app.contracts.base import ContractModel
from app.core.ids import sha256_text, stable_id
from app.core.time import utc_now
from app.normalizers.base import AdapterError
from app.detection import DetectionEngine
from app.entities import EntityResolver
from app.graph.ports import GraphProjector
from app.normalizers import NormalizerRegistry
from app.repositories import SQLiteRepository
from app.sessions import Sessionizer

from .service import IngestionService


class PipelineResult(ContractModel):
    run_id: str
    accepted_raw: int
    events: List[UnifiedSecurityEvent] = Field(default_factory=list)
    sessions: List[Session] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    detections: List[DetectionResult] = Field(default_factory=list)
    chains: List[AttackChain] = Field(default_factory=list)
    graph_entities: List[GraphEntity] = Field(default_factory=list)
    graph_relations: List[GraphRelation] = Field(default_factory=list)


class AnalysisPipeline:
    version = "1.0.0"

    def __init__(self, ingestion: IngestionService, normalizers: NormalizerRegistry, repository: SQLiteRepository, resolver: EntityResolver, sessionizer: Sessionizer, graph: GraphProjector, detection: DetectionEngine, chains: DeterministicChainBuilder) -> None:
        self.ingestion = ingestion
        self.normalizers = normalizers
        self.repository = repository
        self.resolver = resolver
        self.sessionizer = sessionizer
        self.graph = graph
        self.detection = detection
        self.chains = chains

    def run(self, run_id: str, raws: List[RawEventEnvelope], mode: str = "replay", progress: Optional[Callable[[str], None]] = None) -> PipelineResult:
        def advance(stage: str) -> None:
            if progress:
                progress(stage)

        self.repository.start_run(run_id, mode, {"raw_ids": [item.raw_id for item in raws]}, {"pipeline": self.version})
        accepted, events, sessions, evidence, detections, chains, projected = self._process_batch(run_id, raws, progress=advance)
        self.repository.complete_run(run_id)
        return PipelineResult(run_id=run_id, accepted_raw=len(accepted), events=events, sessions=sessions, evidence=evidence, detections=detections, chains=chains, graph_entities=projected.entities, graph_relations=projected.relations)

    def start_live_run(self, run_id: str, manifest: Optional[dict] = None) -> None:
        base_manifest = {"raw_ids": [], "source": "live"}
        base_manifest.update(manifest or {})
        self.repository.ensure_run(run_id, "live", base_manifest, {"pipeline": self.version}, "running")

    def append_live_batch(self, run_id: str, raws: List[RawEventEnvelope], progress: Optional[Callable[[str], None]] = None) -> PipelineResult:
        if not self.repository.get_run(run_id):
            self.start_live_run(run_id)
        accepted, events, sessions, evidence, detections, chains, projected = self._process_batch(run_id, raws, progress=progress)
        return PipelineResult(run_id=run_id, accepted_raw=len(accepted), events=events, sessions=sessions, evidence=evidence, detections=detections, chains=chains, graph_entities=projected.entities, graph_relations=projected.relations)

    def stop_live_run(self, run_id: str) -> None:
        self.repository.complete_run(run_id, "completed")

    def _process_batch(self, run_id: str, raws: List[RawEventEnvelope], progress: Optional[Callable[[str], None]] = None):
        def advance(stage: str) -> None:
            if progress:
                progress(stage)

        accepted = [item for item in (self.ingestion.accept(raw) for raw in raws) if item is not None]
        self.repository.append_run_raw_ids(run_id, [item.raw_id for item in accepted])
        advance("normalized")
        events: List[UnifiedSecurityEvent] = []
        evidence: List[Evidence] = []
        for raw in accepted:
            try:
                normalized = self.normalizers.normalize(raw)
            except (AdapterError, ValueError, TypeError) as exc:
                self.repository.put_dead_letter(raw.raw_id, "normalize", exc.__class__.__name__, str(exc), raw.raw_ref)
                evidence.append(self._raw_failure_evidence(raw, exc))
                continue
            events.extend(normalized)
            evidence.extend(self._event_evidence(event) for event in normalized)
        advance("entities")
        self.repository.append_events(run_id, events)
        self.repository.put_evidence(run_id, evidence)
        all_events = self.repository.all_events(run_id)
        sessions = self.sessionizer.build(all_events)
        self.repository.put_sessions(run_id, sessions)
        facts = self.resolver.resolve(all_events, sessions)
        advance("host_network")
        self.graph.project(facts)
        all_evidence = self.repository.all_evidence(run_id)
        advance("detections")
        detections = self.detection.evaluate(run_id, all_events, sessions, all_evidence)
        self.repository.put_detections(detections)
        advance("attack")
        projected = self.resolver.resolve(all_events, sessions, detections)
        self.graph.project(projected)
        advance("correlated")
        advance("chains")
        chains = self.chains.build(run_id, detections)
        self.repository.replace_chains_for_run(run_id, chains)
        advance("ready_for_agent")
        return accepted, all_events, sessions, all_evidence, detections, chains, projected

    def _event_evidence(self, event: UnifiedSecurityEvent) -> Evidence:
        excerpt = {"event_time": event.event_time.isoformat(), "source": event.source.kind.value, "action": event.action, "message": event.message}
        return Evidence(
            evidence_id=stable_id("evd", event.event_id, "normalized"), kind="normalized_event",
            source_ref=event.provenance.raw_ref, event_ids=[event.event_id],
            entity_ids=[ref.entity_id for ref in (event.host, event.actor.user, event.actor.process, event.object.ref) if ref],
            excerpt=excerpt, observed_at=event.event_time, collected_at=event.ingested_time,
            producer=event.provenance.parser_name, producer_version=event.provenance.parser_version,
            integrity_sha256=sha256_text(event.model_dump_json()), reliability="direct", supports=[], contradicts=[],
        )

    def _raw_failure_evidence(self, raw: RawEventEnvelope, exc: Exception) -> Evidence:
        excerpt = {
            "source": raw.source.kind.value,
            "dataset": raw.source.dataset,
            "raw_ref": raw.raw_ref,
            "error": str(exc),
            "payload": raw.payload if isinstance(raw.payload, str) else raw.payload,
        }
        return Evidence(
            evidence_id=stable_id("evd", raw.raw_id, "normalize_failed"),
            kind="raw_event",
            source_ref=raw.raw_ref,
            event_ids=[],
            entity_ids=[],
            excerpt=excerpt,
            observed_at=raw.observed_time,
            collected_at=raw.ingested_time or utc_now(),
            producer="normalizer",
            producer_version=self.version,
            integrity_sha256=raw.raw_sha256,
            reliability="direct",
            supports=[],
            contradicts=[],
        )
