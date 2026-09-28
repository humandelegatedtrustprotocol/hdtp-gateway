-- +goose Up
-- The change log (SPEC sec. 7.8): one row for every event the node publishes - a message, a
-- request, a pending call, a delivery, a call, an attention, an answer - so that every node
-- process sharing this store learns what another wrote. The id is the cursor: store-assigned,
-- and committed in id order (SQLite writes one transaction at a time; on Postgres every insert
-- takes the one change lock first). The owner MCP's wait_for_updates answers with it. Rows are
-- kept for a week (the hourly retention pass).
CREATE TABLE changes (
    id          BIGSERIAL PRIMARY KEY,
    account_id  TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    thread_id   TEXT NOT NULL DEFAULT '',
    contact_fpr TEXT NOT NULL DEFAULT '',
    ref         TEXT NOT NULL DEFAULT '',
    at          BIGINT NOT NULL
);
CREATE INDEX changes_at ON changes(at);
-- wait_for_updates reads one account's changes after its cursor.
CREATE INDEX changes_account ON changes(account_id, id);

-- +goose Down
DROP TABLE changes;
