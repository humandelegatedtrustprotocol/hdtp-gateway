-- +goose Up
-- Outbound webhooks (docs/release/webhooks-2026-10-18.md, W1 and W2).
--
-- A message's change row names the message and its direction, and the kind of the message, so
-- the webhooks of the node can tell `message.received` from `media.received` and from a message
-- the node sent; a delivery-status row names the message whose status changed. Every other row
-- keeps them empty.
ALTER TABLE changes ADD COLUMN msg_id text DEFAULT ''::text NOT NULL;
ALTER TABLE changes ADD COLUMN direction text DEFAULT ''::text NOT NULL;
ALTER TABLE changes ADD COLUMN msg_kind text DEFAULT ''::text NOT NULL;

-- Where one identity's events are posted. The signing secret is sealed with the node's keyring
-- (internal/services/webhooks/seal.go), the previous one too while a rotation lasts. Times are
-- unix MILLISECONDS, as the cloud's are, because the views and the envelope carry them to a
-- receiver that may serve both hosts.
CREATE TABLE webhook_endpoints (
    id text NOT NULL,
    account_id text NOT NULL,
    url text NOT NULL,
    events text DEFAULT '[]'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    failures bigint DEFAULT 0 NOT NULL,
    secret_sealed bytea NOT NULL,
    previous_sealed bytea,
    previous_until bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id),
    CONSTRAINT webhook_endpoints_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT webhook_endpoints_status_check CHECK (status IN ('active', 'paused'))
);
CREATE INDEX webhook_endpoints_account ON webhook_endpoints (account_id, created_at);

-- One attempt each, and never a retry. A row outlives its endpoint: the log keeps naming it.
CREATE TABLE webhook_deliveries (
    id text NOT NULL,
    account_id text NOT NULL,
    endpoint_id text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    status text NOT NULL,
    http_status bigint,
    latency_ms bigint NOT NULL,
    excerpt text DEFAULT ''::text NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT webhook_deliveries_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('delivered', 'failed'))
);
CREATE INDEX webhook_deliveries_endpoint ON webhook_deliveries (account_id, endpoint_id, created_at);
-- The retention pass deletes by created_at alone, across every account and endpoint (#218).
CREATE INDEX webhook_deliveries_created ON webhook_deliveries (created_at);

-- How far the dispatcher has read each identity's change log: the id of the last change it
-- claimed. A claim moves the cursor from the id it read, so two node processes on one store never
-- both post one change (internal/services/webhooks/dispatch.go).
CREATE TABLE webhook_cursor (
    account_id text NOT NULL,
    last_change_id bigint NOT NULL,
    CONSTRAINT webhook_cursor_pkey PRIMARY KEY (account_id),
    CONSTRAINT webhook_cursor_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE webhook_cursor;
DROP TABLE webhook_deliveries;
DROP TABLE webhook_endpoints;
ALTER TABLE changes DROP COLUMN msg_kind;
ALTER TABLE changes DROP COLUMN direction;
ALTER TABLE changes DROP COLUMN msg_id;
