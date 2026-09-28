-- +goose Up
-- When the owner's agent last asked the owner MCP anything (SPEC sec. 6.8): one row, so that every
-- node process sharing the store answers "is the agent attached" the same. Written at most once
-- per few seconds per process.
CREATE TABLE owner_presence (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    seen_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE owner_presence;
