-- +goose Up
-- accounts.protocol began as the generation an account spoke. With one generation left it had
-- come to mean something else entirely: 1 was "no leaf installed yet" and 2 was "the wallet has
-- issued one" - a live 2.0 state, stored under a retired generation's number. It was also a
-- duplicate. The only statement that ever wrote it set root_fingerprint in the same breath, always
-- to 2 and always with a root, so "protocol = 2" and "root_fingerprint IS NOT NULL" were one fact
-- kept in two places. The code now asks the question it meant: does this account have a root.
ALTER TABLE accounts DROP COLUMN protocol;

-- +goose Down
-- Re-created as 0027 made it, then set from the fact it duplicated, so a rolled-back schema reads
-- the way the old code expects and 0027's own Down finds the column it drops.
ALTER TABLE accounts ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1;
UPDATE accounts SET protocol = 2 WHERE root_fingerprint IS NOT NULL AND root_fingerprint <> '';
