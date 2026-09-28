-- +goose Up
-- Background work only one node process on the store may do at a time (SPEC sec. 11.1): the
-- outbound retries, the hourly retention pass. A process does it while it holds the work's lease,
-- renewing it as it goes (taken_at is when it last did); a lease past expires_at is anyone's.
CREATE TABLE leases (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    taken_at   INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE leases;
