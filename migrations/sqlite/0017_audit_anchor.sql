-- +goose Up
-- The audit chain's anchor (SPEC §11.6). Archiving moves old rows to a JSONL
-- file and re-anchors what remains: the terminal hash of the archived segment
-- is recorded here, so `audit verify` can tell "these rows extend an archive I
-- know about" from "someone deleted the oldest rows". Without a durable anchor,
-- a truncated head is indistinguishable from a short chain.
--
-- Exactly one row, enforced by the primary key.
CREATE TABLE audit_anchor (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    archived_through_seq INTEGER NOT NULL,
    terminal_hash        TEXT NOT NULL,
    archive_path         TEXT NOT NULL,
    updated_at           INTEGER NOT NULL
);

-- The append-only guard becomes precise instead of absolute: UPDATE stays
-- forbidden outright, and DELETE is permitted ONLY for rows the anchor says have
-- already been archived. Archiving records the anchor before it prunes, so the
-- engine — not a convention in application code — is what stops rows being
-- removed without a re-anchor.
-- +goose StatementBegin
DROP TRIGGER audit_events_no_delete;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_events_delete_only_archived BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events: only rows already archived and anchored may be pruned')
    WHERE NOT EXISTS (
        SELECT 1 FROM audit_anchor WHERE id = 1 AND archived_through_seq >= OLD.seq
    );
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER audit_events_delete_only_archived;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
-- +goose StatementEnd
DROP TABLE audit_anchor;
