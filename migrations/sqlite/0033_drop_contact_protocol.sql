-- +goose Up
-- contacts.protocol told a key-pinned 1.x contact from a root-pinned 2.0 one. There is one kind
-- now, so the column says 2 on every row: every InsertContact wrote 2 or left it unset, and the
-- store mapped unset to 2 with a comment conceding "there is no other generation now". A column
-- that can hold one value holds none, and the branches that read it kept a 1.x fallback alive in
-- code that could never reach it.
ALTER TABLE contacts DROP COLUMN protocol;

-- +goose Down
-- Re-created so rolling the whole schema back does not meet 0027's own Down dropping a column this
-- migration already took. DEFAULT 2, not 0027's 1: every row this could apply to is a 2.0 pin.
ALTER TABLE contacts ADD COLUMN protocol INTEGER NOT NULL DEFAULT 2;
