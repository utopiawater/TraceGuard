from datetime import datetime

import pytest
from pydantic import ValidationError

from app.collectors import envelope_from_payload
from app.contracts import SourceDescriptor


def test_raw_envelope_id_is_deterministic():
    source = SourceDescriptor(kind="zeek", product="Zeek", dataset="zeek.conn", sensor_id="z1", source_record_id="uid-1")
    observed = datetime.fromisoformat("2026-09-07T08:00:00+00:00")
    first = envelope_from_payload(source, {"uid": "uid-1"}, "json", 1.0, "fixture://one", observed)
    second = envelope_from_payload(source, {"uid": "uid-1"}, "json", 1.0, "fixture://two", observed)
    assert first.raw_id == second.raw_id
    assert len(first.raw_sha256) == 64


def test_contract_rejects_naive_datetime():
    source = SourceDescriptor(kind="zeek", product="Zeek", dataset="zeek.conn", sensor_id="z1")
    with pytest.raises(ValidationError):
        envelope_from_payload(source, {}, "json", 1.0, "fixture://one", datetime(2026, 9, 7))

