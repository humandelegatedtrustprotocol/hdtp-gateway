-- +goose Up
-- A contact's display_name is the FN from the card THAT CONTACT supplied, so it
-- is theirs to choose and two of them may legitimately match — several people
-- really are called the same thing. The petname is the owner's own name for a
-- contact: optional, local, and unreachable by any peer, which is what makes it
-- the only name a peer cannot influence. Empty means "no opinion, use theirs".
ALTER TABLE contacts ADD COLUMN petname TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE contacts DROP COLUMN petname;
