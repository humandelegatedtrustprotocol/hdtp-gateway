-- +goose Up
-- SPEC §11.2 idempotency: recorded acknowledgments keyed by caller + msg_id so
-- replays return the original ack without re-executing (booking acks live here).
CREATE TABLE idempotency (
    account_id  TEXT NOT NULL,
    contact_fpr TEXT NOT NULL,
    msg_id      TEXT NOT NULL,
    ack         TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    PRIMARY KEY (account_id, contact_fpr, msg_id)
);

-- +goose Down
DROP TABLE idempotency;
