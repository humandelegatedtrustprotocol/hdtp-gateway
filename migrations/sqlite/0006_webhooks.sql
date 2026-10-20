-- +goose Up
-- Outbound webhooks (docs/release/webhooks-2026-10-18.md, W1 and W2).
--
-- A message's change row names the message and its direction, and the kind of the message, so
-- the webhooks of the node can tell `message.received` from `media.received` and from a message
-- the node sent; a delivery-status row names the message whose status changed. Every other row
-- keeps them empty.
ALTER TABLE changes ADD COLUMN msg_id TEXT NOT NULL DEFAULT '';
ALTER TABLE changes ADD COLUMN direction TEXT NOT NULL DEFAULT '';
ALTER TABLE changes ADD COLUMN msg_kind TEXT NOT NULL DEFAULT '';

-- Where one identity's events are posted. The signing secret is sealed with the node's keyring
-- (internal/services/webhooks/seal.go), the previous one too while a rotation lasts. Times are
-- unix MILLISECONDS, as the cloud's are, because the views and the envelope carry them to a
-- receiver that may serve both hosts.
CREATE TABLE webhook_endpoints (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
    failures INTEGER NOT NULL DEFAULT 0,
    secret_sealed BLOB NOT NULL,
    previous_sealed BLOB,
    previous_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX webhook_endpoints_account ON webhook_endpoints(account_id, created_at);

-- One attempt each, and never a retry. A row outlives its endpoint: the log keeps naming it.
CREATE TABLE webhook_deliveries (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('delivered', 'failed')),
    http_status INTEGER,
    latency_ms INTEGER NOT NULL,
    excerpt TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX webhook_deliveries_endpoint ON webhook_deliveries(account_id, endpoint_id, created_at);
-- The retention pass deletes by created_at alone, across every account and endpoint (#218).
CREATE INDEX webhook_deliveries_created ON webhook_deliveries(created_at);

-- How far the dispatcher has read each identity's change log: the id of the last change it
-- claimed. A claim moves the cursor from the id it read, so two node processes on one store never
-- both post one change (internal/services/webhooks/dispatch.go).
CREATE TABLE webhook_cursor (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    last_change_id INTEGER NOT NULL
);

-- +goose Down
DROP TABLE webhook_cursor;
DROP TABLE webhook_deliveries;
DROP TABLE webhook_endpoints;
ALTER TABLE changes DROP COLUMN msg_kind;
ALTER TABLE changes DROP COLUMN direction;
ALTER TABLE changes DROP COLUMN msg_id;
