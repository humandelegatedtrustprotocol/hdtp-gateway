-- +goose Up
-- SPEC §6.8 agent-answered calls: parked rows the owner's agent answers.
-- Arguments are peer-supplied untrusted content, stored raw.
CREATE TABLE pending_requests (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    capability  TEXT NOT NULL,
    args        TEXT NOT NULL,
    trust_flag  TEXT NOT NULL DEFAULT 'messages_only',
    status      TEXT NOT NULL DEFAULT 'open',
    result      TEXT NOT NULL DEFAULT '',
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    answered_at BIGINT
);
CREATE INDEX pending_account_status ON pending_requests(account_id, status);

-- +goose Down
DROP TABLE pending_requests;
