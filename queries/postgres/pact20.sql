-- PACT 2.0 state (SPEC §2, §14; migration 0027): the account's root and leaf
-- ledger, 2.0 pins, the removal tombstone, former endpoints, and the
-- addresses awaiting the owner under `accept_new_hosts = ask`.

-- name: SetAccountProtocol :execrows
UPDATE accounts SET protocol = $1, root_fingerprint = $2, root_cert = $3 WHERE id = $4;

-- name: SetAccountLeafKey :execrows
-- Re-points the account at its CURRENT leaf key. SetAccountKey binds once and
-- never moves; a leaf install moves it, keeping every fingerprint-keyed path
-- (routing, audit, pins) on the key that signs and seals today.
UPDATE accounts SET fingerprint = $1, key_sealed = $2, algo = $3 WHERE id = $4;

-- name: SetAccountHostPolicy :execrows
UPDATE accounts SET accept_new_hosts = $1, accept_1x = $2 WHERE id = $3;

-- name: InsertLeaf :exec
INSERT INTO leaves (account_id, kid, leaf, key_sealed, not_before, not_after, state, endpoint, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: UpdateLeaf :execrows
UPDATE leaves SET leaf = $1, not_before = $2, not_after = $3, state = $4, endpoint = $5 WHERE account_id = $6 AND kid = $7;

-- name: ListLeaves :many
SELECT * FROM leaves WHERE account_id = $1 ORDER BY created_at, kid;

-- name: RetireLeafKey :execrows
-- A superseded leaf past its not_after: the key is destroyed, the kid kept so
-- an envelope still sealed to it is answered certificate_renewed (PACT §14.4).
UPDATE leaves SET key_sealed = NULL, state = 'former' WHERE account_id = $1 AND kid = $2;

-- name: DeleteLeavesByState :execrows
DELETE FROM leaves WHERE account_id = $1 AND state = $2;

-- name: UpsertTombstone :exec
INSERT INTO tombstones (account_id, root, leaf, at) VALUES ($1, $2, $3, $4)
ON CONFLICT (account_id, root) DO UPDATE SET leaf = excluded.leaf, at = excluded.at;

-- name: ListTombstones :many
SELECT * FROM tombstones WHERE account_id = $1 ORDER BY at, root;

-- name: DeleteTombstone :execrows
DELETE FROM tombstones WHERE account_id = $1 AND root = $2;

-- name: InsertFormerEndpoint :exec
INSERT INTO former_endpoints (account_id, root, endpoint, at) VALUES ($1, $2, $3, $4);

-- name: ListFormerEndpoints :many
SELECT * FROM former_endpoints WHERE account_id = $1 ORDER BY at, root, endpoint;

-- name: UpsertPendingAddress :exec
INSERT INTO pending_addresses (account_id, root, endpoint, leaf, why, at) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (account_id, root) DO UPDATE SET endpoint = excluded.endpoint, leaf = excluded.leaf, why = excluded.why, at = excluded.at;

-- name: ListPendingAddresses :many
SELECT * FROM pending_addresses WHERE account_id = $1 ORDER BY at, root;

-- name: GetPendingAddress :one
SELECT * FROM pending_addresses WHERE account_id = $1 AND root = $2;

-- name: DeletePendingAddress :execrows
DELETE FROM pending_addresses WHERE account_id = $1 AND root = $2;

-- name: RepinContactAddress :execrows
-- The 2.0 pin moves: a renewal at the pinned endpoint or an accepted new
-- address replaces the leaf, its key and the endpoint; the root (the
-- fingerprint column) never moves (PACT §14.3, §5.3).
UPDATE contacts SET endpoint = $1, leaf = $2, spki = $3, pinned_at = $4 WHERE account_id = $5 AND fingerprint = $6;

-- name: SetContactChainSentKid :execrows
UPDATE contacts SET chain_sent_kid = $1 WHERE account_id = $2 AND fingerprint = $3;

-- name: ClearChainSentKids :execrows
-- After a leaf install every contact must see the new chain once (PACT §13.2).
UPDATE contacts SET chain_sent_kid = '' WHERE account_id = $1;

-- name: UpgradeContactPin :execrows
-- Appendix C row 6: a 1.x pin of key K, met by a chain whose leaf key is K,
-- becomes a 2.0 pin of the root with no human step.
UPDATE contacts SET fingerprint = $1, protocol = 2, endpoint = $2, leaf = $3, spki = $4, pinned_at = $5 WHERE account_id = $6 AND fingerprint = $7;
