-- +goose Up
-- When a request was made (SPEC sec. 9.1: an unanswered request expires). The sweep read
-- created_at, which is when the CONTACT was added: right for a row inserted as a request, and wrong
-- for a contact the handshake after an import turns into one (PACT sec. 9.2), which keeps the date
-- the contact was first known. Such a row was swept within the hour once that date was older than
-- the window, taking its pin and its permissions with it. Every statement that puts a row into
-- pending_in or pending_out sets requested_at; the sweep reads it and nothing else.
ALTER TABLE contacts ADD COLUMN requested_at BIGINT;
UPDATE contacts SET requested_at = created_at WHERE status IN ('pending_in', 'pending_out');
CREATE INDEX contacts_pending_requested ON contacts(account_id, requested_at) WHERE status IN ('pending_in', 'pending_out');

-- handshake_due (migration 0042) now holds WHEN the contact became owed the handshake - the time
-- of the import that wrote it, 0 when nothing is owed - so the campaign of a leaf requested BEFORE
-- the import does not spend it: the handshake is owed from the identity's next leaf.

-- Whether installing this leaf moved the identity (PACT sec. 5.3, sec. 9), as the install decided
-- it. A move's campaign tells every active contact; any other leaf's campaign is the handshake an
-- import left owed and nothing more. A resumed campaign reads the install's decision here rather
-- than working it out again. A current leaf whose campaign has already recorded progress was, before
-- this column, the leaf of a campaign that walked every active contact, and is marked so.
ALTER TABLE leaves ADD COLUMN moved BIGINT NOT NULL DEFAULT 0;
UPDATE leaves SET moved = 1 WHERE state = 'current'
    AND EXISTS (SELECT 1 FROM move_fanout f WHERE f.account_id = leaves.account_id AND f.leaf_kid = leaves.kid);

-- +goose Down
ALTER TABLE leaves DROP COLUMN moved;
DROP INDEX contacts_pending_requested;
ALTER TABLE contacts DROP COLUMN requested_at;
