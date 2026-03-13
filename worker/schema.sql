CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sync_entries (
  id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  encrypted_blob TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  server_seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_entries_user_seq ON sync_entries(user_id, server_seq);
