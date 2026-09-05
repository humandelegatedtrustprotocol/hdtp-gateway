-- +goose Up
-- SPEC §10.5 relay mode. The relay stores CIPHERTEXT and metadata only: it can
-- verify a sender's signature (with the mTLS certificate key, §4.8) and enforce
-- the recipient's allow-list without ever opening an envelope.
CREATE TABLE relay_allowlist (
    recipient_fpr TEXT NOT NULL,
    sender_fpr    TEXT NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (recipient_fpr, sender_fpr)
);

CREATE TABLE relay_queue (
    id            TEXT PRIMARY KEY,
    recipient_fpr TEXT NOT NULL,
    sender_fpr    TEXT NOT NULL,
    msg_id        TEXT NOT NULL,
    envelope      TEXT NOT NULL,  -- the sealed envelope, verbatim
    size_bytes    INTEGER NOT NULL,
    queued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL -- min(envelope exp, queued_at + 30 days)
);
CREATE INDEX relay_queue_recipient ON relay_queue(recipient_fpr, queued_at);
CREATE INDEX relay_queue_expiry ON relay_queue(expires_at);

-- +goose Down
DROP TABLE relay_queue;
DROP TABLE relay_allowlist;
