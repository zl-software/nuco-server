-- Relay storage schema. All key and ciphertext columns are opaque to the relay.

CREATE TABLE IF NOT EXISTS devices (
  handle           TEXT PRIMARY KEY,
  identity_key     TEXT NOT NULL,
  auth_key         TEXT NOT NULL,
  registration_id  INTEGER NOT NULL,
  device_id        INTEGER NOT NULL,
  push_kind        TEXT NOT NULL,
  push_token       TEXT,
  push_endpoint    TEXT,
  apns_topic       TEXT,
  created_at       INTEGER NOT NULL,
  last_seen        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_prekeys (
  handle      TEXT PRIMARY KEY REFERENCES devices(handle) ON DELETE CASCADE,
  key_id      INTEGER NOT NULL,
  public_key  TEXT NOT NULL,
  signature   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS onetime_prekeys (
  handle      TEXT NOT NULL REFERENCES devices(handle) ON DELETE CASCADE,
  key_id      INTEGER NOT NULL,
  public_key  TEXT NOT NULL,
  PRIMARY KEY (handle, key_id)
);

CREATE TABLE IF NOT EXISTS queued_messages (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient     TEXT NOT NULL,
  id            TEXT NOT NULL,
  sender        TEXT NOT NULL,
  ciphertext    TEXT NOT NULL,
  message_type  TEXT NOT NULL,
  sent_at       INTEGER NOT NULL,
  enqueued_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_queue_recipient ON queued_messages(recipient, seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_queue_dedupe ON queued_messages(recipient, id);
