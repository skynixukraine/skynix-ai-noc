CREATE TABLE IF NOT EXISTS incidents (
  id BIGSERIAL PRIMARY KEY,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen  TIMESTAMPTZ NOT NULL,
  severity   SMALLINT NOT NULL,      -- 1=P1,2=P2,3=P3
  type       TEXT NOT NULL,
  title      TEXT NOT NULL,
  summary    TEXT NOT NULL,
  host       TEXT,
  service    TEXT,
  fingerprint TEXT NOT NULL UNIQUE,  -- dedupe ключ
  evidence   JSONB NOT NULL DEFAULT '{}'::jsonb,
  counters   JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_open    BOOLEAN NOT NULL DEFAULT TRUE,
  notified_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON incidents(is_open);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(type);

