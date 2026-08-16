-- Custom headers per webhook.
--
-- Receivers usually sit behind something that wants a header of its own: an
-- Authorization bearer for an API gateway, a tenant id, a routing key. Without
-- this the only way to reach such a receiver is to put the secret in the query
-- string of the URL, which is exactly where secrets should not be.
--
-- These are set on the outgoing request BEFORE tokenzy's own headers, so a
-- custom header can never overwrite X-Webhook-Signature and quietly turn a
-- verifiable delivery into an unverifiable one.

ALTER TABLE webhooks ADD COLUMN headers TEXT NOT NULL DEFAULT '{}';
