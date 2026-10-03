-- +goose Up
-- The table is named for what it holds. `rotation_fanout` was the first generation's key rotation's ledger
-- (0014): per-contact progress of the walk that told every contact about a NEW KEY, hence
-- `new_fpr`. Key rotation went with 1.x. What is still worth walking every contact for is a MOVE
-- (HDTP §5.3, §9) — the address in the leaf changed, and nobody would otherwise know — and the
-- fingerprint the rows carry is the kid of the LEAF being announced, which is what a re-run
-- matches on to resume. Same rows, same meaning since 0035; only the names were 1.x's.
--
-- Postgres keeps a constraint's name when its table is renamed, so the key is renamed with it.
ALTER TABLE rotation_fanout RENAME TO move_fanout;
ALTER TABLE move_fanout RENAME COLUMN new_fpr TO leaf_kid;
ALTER TABLE move_fanout RENAME CONSTRAINT rotation_fanout_pkey TO move_fanout_pkey;

-- +goose Down
ALTER TABLE move_fanout RENAME CONSTRAINT move_fanout_pkey TO rotation_fanout_pkey;
ALTER TABLE move_fanout RENAME COLUMN leaf_kid TO new_fpr;
ALTER TABLE move_fanout RENAME TO rotation_fanout;
