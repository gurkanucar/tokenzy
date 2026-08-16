-- One-time codes.
--
-- A separate table from tokens, and separate on purpose: the two have opposite
-- entropy profiles and therefore opposite defences.
--
-- A token carries ~244 bits, so guessing one is not a threat and there is
-- deliberately no attempt counter anywhere near it. A six-digit code is a
-- million possibilities, which a script exhausts in minutes — so here the
-- attempt ceiling *is* the security model, and `max_attempts` is not optional.
-- Putting both in one table would have meant one set of columns pretending to
-- serve two arguments.
--
-- The code is stored in the clear, like the token. It buys the same thing —
-- the panel can show it again — plus one thing tokens do not need: resend. A
-- "send it again" button has to return the code the user was already given,
-- and a hash cannot do that.
CREATE TABLE otps (
  id             TEXT PRIMARY KEY,             -- "otp_" + 32 hex
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,

  -- The caller's own context label: password_reset, email_verify, whatever it
  -- names. Never interpreted here, only matched.
  type           TEXT NOT NULL,

  -- Who the code was issued to, as an opaque string. It is usually an email
  -- address or a phone number, which makes it personal data — hence the short
  -- retention, and hence its absence from logs.
  identifier     TEXT NOT NULL,

  code           TEXT NOT NULL,                -- PLAINTEXT, numeric, 4-10 digits
  attempt_count  INTEGER NOT NULL DEFAULT 0,
  max_attempts   INTEGER NOT NULL DEFAULT 5,
  expires_at     INTEGER NOT NULL,
  consumed_at    INTEGER,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL
);

-- Deliberately no UNIQUE on code. Six-digit codes collide across identifiers
-- constantly and that is fine — the code alone never identifies anything, only
-- the triple (type, identifier, code) does.
--
-- Nor is there a partial unique index enforcing "one active code per
-- (environment, type, identifier)", which is the rule the service actually
-- keeps. The predicate would need `expires_at > now`, and an index cannot
-- contain the current time: a dead-but-not-yet-swept row would sit there
-- blocking every new code for that identifier until the cleanup job happened to
-- run. The rule is enforced in a transaction on the single write connection
-- instead, where it can be stated correctly.

-- Both hot paths go through this: generate looks for an existing active code,
-- and validate matches on all three columns.
--
-- The trailing created_at and id are not decoration. Generate asks for the
-- newest live code, and with the index stopping at identifier SQLite preferred
-- the listing index below — because that one could satisfy the ORDER BY — and
-- then scanned the whole environment looking for one row. Measured at 200k
-- codes: 162ms, inside the write transaction, holding the single write
-- connection. With the ordering carried here it is a precise seek at 0.0ms.
CREATE INDEX idx_otps_lookup
  ON otps(environment_id, type, identifier, created_at DESC, id DESC);

-- The panel listing.
CREATE INDEX idx_otps_env_created ON otps(environment_id, created_at DESC);

-- No index on expires_at, though an earlier draft of the plan called for one.
-- The cleanup sweep is an OR across expires_at, consumed_at and revoked_at, so
-- one column cannot serve it; adding the index left the sweep scanning exactly
-- as before (12.5ms either way at 200k codes) while costing insert throughput
-- and disk. The scan is bounded anyway — this table only ever holds about a
-- day of codes, because that is what the retention window keeps.
