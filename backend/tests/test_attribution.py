from pathlib import Path

from app.attribution import AttackFingerprint, analyze_c2, rank_groups
from app.bootstrap import build_pipeline
from app.core.settings import Settings
from app.graph import InMemoryGraphProjector
from app.knowledge import MappingFileProvider
from app.repositories import SQLiteRepository
from app.scenarios import load_scenario


SCENARIO = Path(__file__).parents[1] / "fixtures" / "scenarios" / "full_attack_chain"
ATTACK = Path(__file__).parents[2] / "knowledge" / "attack" / "mappings.json"


def seeded_chain(tmp_path):
    settings = Settings(data_dir=tmp_path, database_path=tmp_path / "attribution.db", raw_archive_dir=tmp_path / "raw", neo4j_enabled=False)
    repo = SQLiteRepository(settings.database_path)
    graph = InMemoryGraphProjector()
    result = build_pipeline(settings, repo, graph).run("run_attribution_test", load_scenario(SCENARIO))
    return repo, result.chains[0]


def test_attack_fingerprint_generation(tmp_path):
    repo, chain = seeded_chain(tmp_path)
    fingerprint = AttackFingerprint.from_chain(chain, repo)

    assert "T1059.001" in fingerprint.techniques
    assert any("powershell" in item.lower() for item in fingerprint.process_name)
    assert "encoded_powershell" in fingerprint.command_pattern
    assert "203.0.113.77" in fingerprint.ip


def test_c2_analysis_uses_offline_intel_snapshot(tmp_path):
    repo, chain = seeded_chain(tmp_path)
    profiles = analyze_c2(AttackFingerprint.from_chain(chain, repo))

    assert any(profile.asn == "AS64512 LAB-NET" for profile in profiles)
    assert any(profile.tls_fingerprint for profile in profiles)
    assert any("203.0.113.77" in profile.historical_ip for profile in profiles)


def test_apt_matching_returns_top_three_candidates(tmp_path):
    repo, chain = seeded_chain(tmp_path)
    fingerprint = AttackFingerprint.from_chain(chain, repo)
    profiles = analyze_c2(fingerprint)
    groups = MappingFileProvider(ATTACK).groups()
    candidates = rank_groups(fingerprint, profiles, groups)

    assert len(candidates) == 3
    assert all({"group", "confidence", "matched_features"} <= set(candidate) for candidate in candidates)
    assert candidates[0]["confidence"] >= candidates[-1]["confidence"]
    assert any(candidate["group"] == "APT29" for candidate in candidates)
