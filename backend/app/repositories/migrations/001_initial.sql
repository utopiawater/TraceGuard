PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('live','replay','snapshot')),
  status TEXT NOT NULL,
  input_manifest_json TEXT NOT NULL DEFAULT '{}',
  versions_json TEXT NOT NULL DEFAULT '{}',
  started_at TEXT NOT NULL,
  completed_at TEXT,
  errors_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS raw_events (
  raw_id TEXT PRIMARY KEY,
  source_kind TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  source_record_id TEXT,
  event_time_raw TEXT,
  observed_time TEXT NOT NULL,
  ingested_time TEXT NOT NULL,
  raw_ref TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  labels_json TEXT NOT NULL,
  envelope_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_raw_source_time ON raw_events(source_kind, observed_time);

CREATE TABLE IF NOT EXISTS normalized_events (
  event_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  event_time TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  host_id TEXT,
  action TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  raw_id TEXT NOT NULL,
  event_json TEXT NOT NULL,
  FOREIGN KEY(raw_id) REFERENCES raw_events(raw_id)
);
CREATE INDEX IF NOT EXISTS ix_events_time ON normalized_events(event_time);
CREATE INDEX IF NOT EXISTS ix_events_host_action ON normalized_events(host_id, action);
CREATE INDEX IF NOT EXISTS ix_events_run ON normalized_events(run_id);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  session_type TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT,
  host_id TEXT,
  user_id TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  state TEXT NOT NULL,
  session_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sessions_time ON sessions(start_time, end_time);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  observed_at TEXT,
  reliability TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
  detection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  detection_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_detections_run_severity ON detections(run_id, severity);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  detection_id TEXT NOT NULL UNIQUE,
  case_id TEXT,
  status TEXT NOT NULL,
  assignee TEXT,
  disposition TEXT NOT NULL,
  notes_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(detection_id) REFERENCES detections(detection_id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
  chain_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  score REAL NOT NULL,
  chain_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_tasks (
  task_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  agent_role TEXT NOT NULL,
  state TEXT NOT NULL,
  parent_task_id TEXT,
  task_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_results (
  result_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id)
);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  format TEXT NOT NULL,
  version TEXT NOT NULL,
  artifact_ref TEXT NOT NULL,
  evidence_ids_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dead_letters (
  dead_letter_id TEXT PRIMARY KEY,
  raw_id TEXT,
  stage TEXT NOT NULL,
  error_code TEXT NOT NULL,
  error_message TEXT NOT NULL,
  payload_ref TEXT,
  created_at TEXT NOT NULL
);

