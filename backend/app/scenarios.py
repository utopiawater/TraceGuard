import json
from pathlib import Path
from typing import List

from app.collectors import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.core.time import parse_timestamp


def load_scenario(root: Path) -> List[RawEventEnvelope]:
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    envelopes = []
    for record in manifest["records"]:
        path = root / record["file"]
        payload = json.loads(path.read_text(encoding="utf-8")) if record["format"] == "json" else path.read_text(encoding="utf-8")
        payloads = payload if record.get("batch") and isinstance(payload, list) else [payload]
        for index, item in enumerate(payloads):
            record_id = record["source_record_id"] + ("-%d" % index if len(payloads) > 1 else "")
            event_time_raw = item.get("ts", record["event_time_raw"]) if isinstance(item, dict) else record["event_time_raw"]
            source = SourceDescriptor(
                kind=record["source_kind"], product=record.get("product") or ("Microsoft Windows" if record["source_kind"] not in {"zeek", "auditd", "wazuh"} else record["source_kind"].title()),
                dataset=record["dataset"], sensor_id=record["sensor_id"], host_hint=record.get("host_hint") or ("win-client-01.corp.lab" if record["source_kind"] != "zeek" else "10.10.20.15"),
                source_record_id=record_id,
            )
            observed = parse_timestamp(event_time_raw)
            envelopes.append(envelope_from_payload(
                source=source, payload=item, payload_format=record["format"], event_time_raw=event_time_raw,
                raw_ref="fixture://%s/%s%s" % (manifest["scenario_id"], record["file"], "#%d" % index if len(payloads) > 1 else ""), observed_time=observed,
                labels={"scenario_id": manifest["scenario_id"], "ground_truth_ref": "manifest.json#ground_truth", "traffic_class": record.get("traffic_class")},
            ))
    return envelopes
