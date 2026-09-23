-- +goose Up
-- Whether this relationship was ever active: what an unblock needs to know (SPEC sec. 9.1).
--
-- Two kinds of row reach `blocked` and they are undone differently. A contact the owner blocked
-- was active, and unblocking restores it with its grant as it was. A request the owner rejected
-- (`pending_in`), or an approach of ours the peer declined (`pending_out`), was never a contact:
-- unblocking forgets the row, so they are a stranger again who may ask again. `pinned_at` cannot
-- tell them apart on this node - a pending row is pinned when it is written - so the store keeps
-- the fact itself, set by every statement that makes a row active and cleared by none.
--
-- The backfill marks what is active now. A row blocked before this migration was blocked by a
-- rejection or an import - this node had no way for an owner to block an active contact - so
-- none of them was a contact the owner blocked, and 0 is true of each.
ALTER TABLE contacts ADD COLUMN ever_active INTEGER NOT NULL DEFAULT 0;
UPDATE contacts SET ever_active = 1 WHERE status = 'active';

-- +goose Down
ALTER TABLE contacts DROP COLUMN ever_active;
