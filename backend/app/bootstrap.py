from pathlib import Path
from typing import Optional

from app.attack import DeterministicChainBuilder
from app.core.settings import Settings
from app.detection import DetectionEngine, RuleRegistry
from app.detection.covert import DnsTunnelRule, HttpCovertChannelRule, IcmpTunnelRule
from app.detection.rules import (AnchoredPeerTrafficRule, ArchiveCollectedDataRule,
    ArchiveTransferCorrelationRule, BeaconingSessionRule, CollectionArchiveCorrelationRule,
    CrossSourceNetworkRule, DataExfiltrationRule, ExecutionCleanupRule,
    FlowNetworkServiceScanningRule, ForkExecTempRule, HttpC2CandidateRule,
    IngressToolTransferRule, LateralMovementRule, MemoryTamperingRule, NetworkServiceScanningRule,
    PermissionThenExecutionRule, PrivilegeEscalationRule, RegistryPersistenceRule,
    RemoteInteractiveLogonRule, SensitiveFileCollectionRule, SensitiveReadBurstRule, ServiceProcessExternalConnectionRule,
    ServiceSpawnShellRule, SuspiciousFileStagingRule, SuspiciousHttpClientTransferRule,
    SuspiciousPowerShellRule, SuspiciousServiceSessionRule, TempDirectoryExecutionRule,
    TempExecNetworkRule, TempFileLifecycleRule, WebProbingRule)
from app.entities import EntityResolver
from app.graph import InMemoryGraphProjector, RuntimeGraphProjector
from app.ingestion import IngestionService, RawArchive
from app.ingestion.pipeline import AnalysisPipeline
from app.knowledge import AttackMappingRegistry, MappingFileProvider
from app.normalizers import ApplicationWebAdapter, AuditdAdapter, DarpaTcE3CadetsAdapter, NormalizerRegistry, SampleAttackDatasetAdapter, SysmonAdapter, WindowsSecurityAdapter, WazuhAdapter, ZeekAdapter
from app.normalizers.pending import DatasetAdapter
from app.repositories import SQLiteRepository
from app.sessions import Sessionizer


def build_pipeline(settings: Settings, repository: Optional[SQLiteRepository] = None, graph=None) -> AnalysisPipeline:
    settings.ensure_directories()
    repo = repository or SQLiteRepository(settings.database_path)
    projector = graph or RuntimeGraphProjector(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password, settings.neo4j_enabled, Path(__file__).parents[2] / "deploy" / "neo4j" / "schema.cypher")
    provider = MappingFileProvider(Path(__file__).parents[2] / "knowledge" / "attack" / "mappings.json")
    normalizers = NormalizerRegistry([
        SysmonAdapter(), WindowsSecurityAdapter(), ZeekAdapter(), WazuhAdapter(), AuditdAdapter(),
        DarpaTcE3CadetsAdapter(), SampleAttackDatasetAdapter(), ApplicationWebAdapter(), DatasetAdapter(),
    ])
    rules = RuleRegistry([
        RemoteInteractiveLogonRule(), SuspiciousPowerShellRule(), CrossSourceNetworkRule(),
        LateralMovementRule(), PrivilegeEscalationRule(), SensitiveFileCollectionRule(),
        DataExfiltrationRule(), RegistryPersistenceRule(), MemoryTamperingRule(),
        TempDirectoryExecutionRule(), ServiceProcessExternalConnectionRule(), NetworkServiceScanningRule(),
        FlowNetworkServiceScanningRule(), HttpC2CandidateRule(), WebProbingRule(),
        ArchiveCollectedDataRule(), SuspiciousHttpClientTransferRule(),
        TempFileLifecycleRule(), PermissionThenExecutionRule(), ExecutionCleanupRule(),
        ServiceSpawnShellRule(), TempExecNetworkRule(), SuspiciousServiceSessionRule(),
        AnchoredPeerTrafficRule(), BeaconingSessionRule(), SensitiveReadBurstRule(),
        CollectionArchiveCorrelationRule(), ArchiveTransferCorrelationRule(),
        IngressToolTransferRule(), SuspiciousFileStagingRule(), ForkExecTempRule(),
        DnsTunnelRule(), HttpCovertChannelRule(), IcmpTunnelRule(),
    ])
    return AnalysisPipeline(
        ingestion=IngestionService(repo, RawArchive(settings.raw_archive_dir)), normalizers=normalizers,
        repository=repo, resolver=EntityResolver(), sessionizer=Sessionizer(), graph=projector,
        detection=DetectionEngine(rules, AttackMappingRegistry(provider)), chains=DeterministicChainBuilder(),
    )
