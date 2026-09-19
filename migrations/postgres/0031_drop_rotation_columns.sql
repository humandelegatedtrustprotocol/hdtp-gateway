-- +goose Up
-- Key rotation went with PACT 1.x on 2026-09-18: under 2.0 a root is never rotated and a leaf is
-- renewed by the wallet, so there is no retiring key to keep live and no grace window to run.
-- The removal plan called for this migration and it was never written — the slot it named,
-- 0029, went to contact_root_cert — so these three columns outlived every line that read them.
-- No query names them and no hand-written code touches them; they survived in `SELECT * FROM
-- accounts`, which dragged a BYTEA and two dead fields into every account read.
--
-- prev_key_sealed is the one that matters: it could hold a sealed private key from a rotation
-- that was in flight. Dropping the column destroys it, which is what 1.x's own rule asked for
-- when a grace period ended.
ALTER TABLE accounts DROP COLUMN prev_fingerprint;
ALTER TABLE accounts DROP COLUMN prev_key_sealed;
ALTER TABLE accounts DROP COLUMN grace_until;

-- +goose Down
-- Re-created exactly as 0014 made them, so rolling the whole schema back does not meet 0014's
-- own Down dropping columns this migration already took.
ALTER TABLE accounts ADD COLUMN prev_fingerprint TEXT;
ALTER TABLE accounts ADD COLUMN prev_key_sealed BYTEA;
ALTER TABLE accounts ADD COLUMN grace_until BIGINT NOT NULL DEFAULT 0;
