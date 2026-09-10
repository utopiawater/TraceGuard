PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS live_sources_run_scoped (
  run_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('online','offline')),
  last_seen TEXT,
  events_received INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(run_id, source_id)
);

INSERT OR IGNORE INTO live_sources_run_scoped(run_id,source_id,source_type,status,last_seen,events_received,last_error,updated_at)
SELECT '__legacy__', source_id, source_type, status, last_seen, events_received, last_error, updated_at
FROM live_sources;

DROP TABLE live_sources;
ALTER TABLE live_sources_run_scoped RENAME TO live_sources;

CREATE TABLE IF NOT EXISTS live_checkpoints_run_scoped (
  run_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  cursor_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY(run_id, source_id)
);

INSERT OR IGNORE INTO live_checkpoints_run_scoped(run_id,source_id,source_type,cursor_json,updated_at)
SELECT '__legacy__', source_id, source_type, cursor_json, updated_at
FROM live_checkpoints;

DROP TABLE live_checkpoints;
ALTER TABLE live_checkpoints_run_scoped RENAME TO live_checkpoints;

PRAGMA foreign_keys = ON;
