# TraceGuard Release Runbook

## Supported environment

- Windows 10/11 x64
- Python 3.13.x with OpenSSL 3.x; Python 3.8 is not supported
- Node.js 20 or newer
- Neo4j 5.26 Community
- Local FastAPI port: `8000`
- Local frontend port: `5173`
- Neo4j Bolt port: `7687`

Docker uses `python:3.13-slim`. Local development and release verification use the project `.venv`; do not start the backend with an older global Python.

## Installation

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
Copy-Item .env.example .env
```

Fill the local Neo4j and OpenAI-compatible LLM values in `.env`. The file is Git-ignored. Keep `LLM_TIMEOUT_SECONDS=180`; never place the API Key in source, logs, screenshots, reports, or frontend configuration.

## Start, check, and stop

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

`check.ps1` verifies Python/OpenSSL, Python packages, `.env`, non-secret LLM configuration, Neo4j, SQLite, FastAPI, frontend, and LLM reachability. Its output includes only whether an API Key is configured; it never prints the Key.

## Agent demonstration modes

- Quick: `POST /api/chains/{chain_id}/investigate?scope=quick&max_steps=4`
  - Coordinator → Host/Network → Correlation
  - Uses the configured real model, real read-only tools, strict JSON validation, and EvidenceValidator.
- Full: `POST /api/chains/{chain_id}/investigate?scope=full&max_steps=12`
  - Coordinator → Host/Network → Correlation → Attribution → Report

Every task exposes an explicit execution mode: `real_llm`, `deterministic_fallback`, or `pending`. Quick mode does not replace or alter the full six-Agent flow.

## Formal real-model acceptance record

The immutable release evidence for the successful DeepSeek run is:

- Case: `case_1421c3d00365403d`
- AttackChain: `chain_0cf169837ae6850e2e88344d`
- Metadata: `artifacts/release/case_1421c3d00365403d.acceptance.json`
- Reports: `artifacts/release/case_1421c3d00365403d-report.md` and `.html`

Automated tests use a Fake ModelClient and do not consume real LLM tokens.

## Public dataset replay

DARPA TC E3 CADets is the current public dataset acceptance run. It must be replayed through the TraceGuard pipeline, not through a separate analysis script:

```powershell
.\.venv\Scripts\python.exe scripts/replay_dataset.py --dataset datasets/darpa_tc_e3_cadets --data-dir data/dataset_e3 --run-id run_darpa_tc_e3_001 --reset --quick-investigation --agent-fallback
```

Expected current summary:

- `input_records`: 20776
- `normalized_records`: 20776
- `failed_records`: 0
- `detection_count`: 348
- `chain_count`: 1
- report: `data/dataset_e3/dataset_run_report.json`

Ground Truth, official IOC, `attack_graph.json`, `attack_timeline.json`, and `agent_input.json` are evaluation-only and must not be used to create system Detection, ATT&CK mappings, AttackChain steps, or Agent findings.

## Incoming testbed data

Wazuh JSON, Sysmon XML, Auditd compound records, and Zeek JSON can enter the existing Adapter registry and unified pipeline without changing Contracts, SQLite schema, graph model, Detection engine, AttackChain, or Agent architecture. Ground Truth remains evaluation metadata and must not be silently converted into observed evidence.

The physical or cloud 8+ node testbed is owned by the testbed teammates. TraceGuard expects a replay bundle plus a scenario manifest. Keep node deployment screenshots, sensor health screenshots, exported logs, and rollback evidence with the final submission. See `docs/13_cloud_testbed_handoff.md`.
