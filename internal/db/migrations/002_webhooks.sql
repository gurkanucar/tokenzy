-- Webhooks push token lifecycle events to a receiver.
--
-- The one rule that shapes the whole design: a delivery never carries the
-- token itself. The plaintext lives in this database because the panel has to
-- be able to show it again; that is not a licence for it to travel. What goes
-- out is the id, the prefix and the metadata — enough for a receiver to
-- correlate, useless to anyone who intercepts it.

CREATE TABLE webhooks (
  id              INTEGER PRIMARY KEY,
  environment_id  INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  url             TEXT NOT NULL,
  -- Signs the body as sha256 HMAC. Shown in the panel because the receiver
  -- needs it to verify, and holding it grants nothing by itself.
  secret          TEXT NOT NULL,
  -- Comma-separated subscription list; empty means every event.
  events          TEXT NOT NULL DEFAULT '',
  label           TEXT NOT NULL DEFAULT '',
  -- Off by default. The token's payload is the caller's own data and does not
  -- have to reach a third host just because a token changed state.
  include_payload INTEGER NOT NULL DEFAULT 0 CHECK (include_payload IN (0,1)),
  created_at      INTEGER NOT NULL,
  disabled_at     INTEGER
);

CREATE INDEX idx_webhooks_environment_id ON webhooks(environment_id);

-- One row per (event, webhook). Retries are scheduled here rather than held in
-- memory, so a restart mid-backoff resumes instead of dropping the delivery.
CREATE TABLE webhook_deliveries (
  id            INTEGER PRIMARY KEY,
  webhook_id    INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_id      TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  payload       TEXT NOT NULL,
  attempt       INTEGER NOT NULL DEFAULT 0,
  status_code   INTEGER,
  error         TEXT NOT NULL DEFAULT '',
  -- Set while another attempt is due; cleared once the delivery has succeeded
  -- or run out of attempts, so "pending" and "gave up" stay distinguishable.
  next_retry_at INTEGER,
  delivered_at  INTEGER,
  created_at    INTEGER NOT NULL
);

CREATE INDEX idx_webhook_deliveries_hook ON webhook_deliveries(webhook_id, created_at DESC);

-- The queue the retry sweep reads. Partial, so it stays the size of the
-- backlog rather than the size of the delivery history.
CREATE INDEX idx_webhook_deliveries_due ON webhook_deliveries(next_retry_at)
  WHERE delivered_at IS NULL AND next_retry_at IS NOT NULL;
