-- +goose Up
-- The audit trail of an identity that left (HDTP sec. 9, SPEC sec. 3.11, sec. 11.6). After a
-- leave, the rows that name the identity by its account id stay in the live trail for a period
-- (audit_archive_after), and then the node moves them to a file of their own under
-- <data_dir>/audit-archive/. They are rows from the MIDDLE of the chain, so the head anchor of
-- 0017 cannot authorise their deletion: this table does, one row at a time.
--
-- audit_archive_rows is empty except inside the one transaction that moves a segment
-- (Store.ArchiveAuditRows): it lists the seq AND the hash of each row the archive wrote and
-- verified, the delete removes exactly those, and the same transaction empties the table.
CREATE TABLE audit_archive_rows (
    seq  BIGINT PRIMARY KEY,
    hash TEXT NOT NULL
);

-- The hourly sweep asks which identities left long enough ago (ListDueLeaves): the few
-- account_leave rows among a million others, in chain order.
CREATE INDEX audit_events_leaves ON audit_events(seq) WHERE action = 'account_leave';

-- The prune guard admits a second sanctioned delete: a row the head anchor covers (0017), or a
-- row whose seq and hash are listed in audit_archive_rows. Every other DELETE is refused, and
-- UPDATE still is outright.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_prune_guard() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_anchor WHERE id = 1 AND archived_through_seq >= OLD.seq
    ) AND NOT EXISTS (
        SELECT 1 FROM audit_archive_rows WHERE seq = OLD.seq AND hash = OLD.hash
    ) THEN
        RAISE EXCEPTION 'audit_events: only rows already archived and anchored may be pruned';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_prune_guard() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_anchor WHERE id = 1 AND archived_through_seq >= OLD.seq
    ) THEN
        RAISE EXCEPTION 'audit_events: only rows already archived and anchored may be pruned';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
DROP INDEX audit_events_leaves;
DROP TABLE audit_archive_rows;
