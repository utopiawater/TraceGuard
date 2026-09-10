CREATE TABLE IF NOT EXISTS live_sources (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('online','offline')),
  last_seen TEXT,
  events_received INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_checkpoints (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  cursor_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL
);
