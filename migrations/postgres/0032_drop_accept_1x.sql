-- +goose Up
-- accept_1x was a posture knob: whether proofs from key-pinned 1.x peers still resolved. There is
-- no such peer to accept. A build that refuses every `v: 1` envelope and every key-pinned card
-- outright has nothing for this column to switch, and nothing read it: it was written by
-- SetAccountHostPolicy, carried on the Account struct, and consulted by no line of production
-- code. It travelled with accept_new_hosts, which is a live 2.0 setting (HDTP sec. 5.3) and stays.
ALTER TABLE accounts DROP COLUMN accept_1x;

-- +goose Down
-- Re-created exactly as 0027 made it, so rolling the whole schema back does not meet 0027's own
-- Down dropping a column this migration already took.
ALTER TABLE accounts ADD COLUMN accept_1x BIGINT NOT NULL DEFAULT 1;
