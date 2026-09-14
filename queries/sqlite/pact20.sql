-- PACT 2.0 state (SPEC §2, §14; migration 0027): the account's root and leaf
-- ledger, 2.0 pins, the removal tombstone, former endpoints, and the
-- addresses awaiting the owner under `accept_new_hosts = ask`.

-- name: SetAccountProtocol :execrows
UPDATE accounts SET protocol = ?, root_fingerprint = ?, root_cert = ? WHERE id = ?;

-- name: SetAccountLeafKey :execrows
-- Re-points the account at its CURRENT leaf key. SetAccountKey binds once and
-- never moves; a leaf install moves it, keeping every fingerprint-keyed path
-- (routing, audit, pins) on the key that signs and seals today.
UPDATE accounts SET fingerprint = ?, key_sealed = ?, algo = ? WHERE id = ?;

-- name: SetAccountHostPolicy :execrows
UPDATE accounts SET accept_new_hosts = ?, accept_1x = ? WHERE id = ?;

-- name: InsertLeaf :exec
INSERT INTO leaves (account_id, kid, leaf, key_sealed, not_before, not_after, state, endpoint, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateLeaf :execrows
UPDATE leaves SET leaf = ?, not_before = ?, not_after = ?, state = ?, endpoint = ? WHERE account_id = ? AND kid = ?;

-- name: ListLeaves :many
SELECT * FROM leaves WHERE account_id = ? ORDER BY created_at, kid;

-- name: RetireLeafKey :execrows
-- A superseded leaf past its not_after: the key is destroyed, the kid kept so
-- an envelope still sealed to it is answered certificate_renewed (PACT §14.4).
UPDATE leaves SET key_sealed = NULL, state = 'former' WHERE account_id = ? AND kid = ?;

-- name: DeleteLeavesByState :execrows
DELETE FROM leaves WHERE account_id = ? AND state = ?;

-- name: UpsertTombstone :exec
INSERT INTO tombstones (account_id, root, leaf, at) VALUES (?, ?, ?, ?)
ON CONFLICT (account_id, root) DO UPDATE SET leaf = excluded.leaf, at = excluded.at;

-- name: ListTombstones :many
SELECT * FROM tombstones WHERE account_id = ? ORDER BY at, root;

-- name: DeleteTombstone :execrows
DELETE FROM tombstones WHERE account_id = ? AND root = ?;

-- name: InsertFormerEndpoint :exec
INSERT INTO former_endpoints (account_id, root, endpoint, at) VALUES (?, ?, ?, ?);

-- name: ListFormerEndpoints :many
SELECT * FROM former_endpoints WHERE account_id = ? ORDER BY at, root, endpoint;

-- name: UpsertPendingAddress :exec
INSERT INTO pending_addresses (account_id, root, endpoint, leaf, why, at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (account_id, root) DO UPDATE SET endpoint = excluded.endpoint, leaf = excluded.leaf, why = excluded.why, at = excluded.at;

-- name: ListPendingAddresses :many
SELECT * FROM pending_addresses WHERE account_id = ? ORDER BY at, root;

-- name: GetPendingAddress :one
SELECT * FROM pending_addresses WHERE account_id = ? AND root = ?;

-- name: DeletePendingAddress :execrows
DELETE FROM pending_addresses WHERE account_id = ? AND root = ?;

-- name: RepinContactAddress :execrows
-- The 2.0 pin moves: a renewal at the pinned endpoint or an accepted new
-- address replaces the leaf, its key and the endpoint; the root (the
-- fingerprint column) never moves (PACT §14.3, §5.3).
UPDATE contacts SET endpoint = ?, leaf = ?, spki = ?, pinned_at = ? WHERE account_id = ? AND fingerprint = ?;

-- name: SetContactChainSentKid :execrows
UPDATE contacts SET chain_sent_kid = ? WHERE account_id = ? AND fingerprint = ?;

-- name: ClearChainSentKids :execrows
-- After a leaf install every contact must see the new chain once (PACT §13.2).
UPDATE contacts SET chain_sent_kid = '' WHERE account_id = ?;

-- name: UpgradeContactPin :execrows
-- Appendix C row 6: a 1.x pin of key K, met by a chain whose leaf key is K,
-- becomes a 2.0 pin of the root with no human step.
UPDATE contacts SET fingerprint = ?, protocol = 2, endpoint = ?, leaf = ?, spki = ?, pinned_at = ? WHERE account_id = ? AND fingerprint = ?;
