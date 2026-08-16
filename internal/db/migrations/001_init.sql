-- PRAGMAs are set per-connection through the DSN (see db.go), not here.

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE projects (
  id         INTEGER PRIMARY KEY,
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE environments (
  id         INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  slug       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (project_id, slug)
);

-- API keys authenticate the machines. They are hashed: a key is shown once at
-- creation and there is no reason it should ever be displayed again.
CREATE TABLE api_keys (
  id             INTEGER PRIMARY KEY,
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  key_hash       TEXT NOT NULL UNIQUE,
  key_prefix     TEXT NOT NULL,
  scope          TEXT NOT NULL CHECK (scope IN ('consume','write','admin')),
  label          TEXT NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);

CREATE INDEX idx_api_keys_environment_id ON api_keys(environment_id);

-- Tokens are stored in the clear, unlike the API keys above.
--
-- That is a deliberate trade, not an oversight. A token is often something a
-- human carries — a link, a code, a pass to be printed as a QR — and the
-- ability to show it again from the panel is worth having. Hashing would make
-- "reprint that pass" impossible.
--
-- What it buys has to be paid for elsewhere, and those payments are not
-- optional: no log line ever contains a token, listings carry only the prefix,
-- the full value comes back from exactly one admin-scope endpoint, and this
-- database file and its backups are secret material to be permissioned as such.
--
-- The status of a token (active / expired / exhausted / revoked) is not a
-- column. It follows from expires_at, used_count/max_uses and revoked_at, and
-- is computed wherever it is needed, so it can never disagree with the facts.
CREATE TABLE tokens (
  id             TEXT PRIMARY KEY,             -- "tok_" + 32 hex
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  token          TEXT NOT NULL UNIQUE,         -- PLAINTEXT: "tkn_" + 64 hex
  token_prefix   TEXT NOT NULL,                -- first 12 characters, for listings
  payload_json   TEXT NOT NULL,                -- opaque JSON, never interpreted
  max_uses       INTEGER,                      -- NULL means unlimited
  used_count     INTEGER NOT NULL DEFAULT 0,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER
);

CREATE INDEX idx_tokens_env_created ON tokens(environment_id, created_at DESC);

-- Drives the cleanup job's first sweep.
CREATE INDEX idx_tokens_expires ON tokens(expires_at);
