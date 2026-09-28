-- PACT 2.0 state (SPEC sec. 2, sec. 14; migration 0027): the account's root and leaf
-- ledger, 2.0 pins, the removal tombstone, former endpoints, and the
-- addresses awaiting the owner under `accept_new_hosts = ask`.

-- name: SetAccountRoot :execrows
-- The first leaf installed names the account's root; the root never changes after (PACT sec. 2).
UPDATE accounts SET root_fingerprint = $1, root_cert = $2 WHERE id = $3;

-- name: SetAccountLeafKey :execrows
-- Re-points the account at its CURRENT leaf key. SetAccountKey binds once and
-- never moves; a leaf install moves it, keeping every fingerprint-keyed path
-- (routing, audit, pins) on the key that signs and seals today.
UPDATE accounts SET fingerprint = $1, key_sealed = $2, algo = $3 WHERE id = $4;

-- name: ClearAccountKey :execrows
-- The account's copy of its CURRENT leaf's key, destroyed when that leaf expires. The leaf ledger
-- row is retired by RetireLeafKey; this is the other place the same key is held. The fingerprint
-- stays: it is how every pin, route and audit row names this account, and it names a key the
-- account no longer has - which is exactly what "awaiting a leaf" means.
UPDATE accounts SET key_sealed = NULL WHERE id = $1;

-- name: SetAccountHostPolicy :execrows
UPDATE accounts SET accept_new_hosts = $1 WHERE id = $2;

-- name: InsertLeaf :exec
INSERT INTO leaves (account_id, kid, leaf, key_sealed, not_before, not_after, state, endpoint, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: UpdateLeaf :execrows
UPDATE leaves SET leaf = $1, not_before = $2, not_after = $3, state = $4, endpoint = $5 WHERE account_id = $6 AND kid = $7;

-- name: SetLeafMoved :execrows
-- Whether installing this leaf moved the identity, as the install decided it (migration 0043): what
-- a resumed campaign reads to know whom it walks.
UPDATE leaves SET moved = $1 WHERE account_id = $2 AND kid = $3;

-- name: ListLeaves :many
SELECT * FROM leaves WHERE account_id = $1 ORDER BY created_at, kid;

-- name: ListKidsExcept :many
-- Every leaf kid on this node that does NOT belong to one account. RecipientState asks
-- this once per inbound envelope, to tell a kid held for a SIBLING identity from
-- one this endpoint never held (PACT sec. 13.3, sec. 14.4). It used to be one
-- query per other account, so the cost of every message grew with the number of
-- identities the node hosts.
SELECT account_id, kid FROM leaves WHERE account_id != $1 ORDER BY account_id, kid;

-- name: RetireLeafKey :execrows
-- A superseded leaf past its not_after: the key is destroyed, the kid kept so
-- an envelope still sealed to it is answered certificate_renewed (PACT sec. 14.4).
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
INSERT INTO pending_addresses (account_id, root, endpoint, leaf, why, at, root_cert) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (account_id, root) DO UPDATE SET endpoint = excluded.endpoint, leaf = excluded.leaf, why = excluded.why, at = excluded.at,
  -- A later note for the same root must not erase a certificate already kept: the
  -- envelope path has none to offer, and the root of a pending address cannot change.
  root_cert = COALESCE(excluded.root_cert, pending_addresses.root_cert);

-- name: ListPendingAddresses :many
SELECT * FROM pending_addresses WHERE account_id = $1 ORDER BY at, root;

-- name: GetPendingAddress :one
SELECT * FROM pending_addresses WHERE account_id = $1 AND root = $2;

-- name: DeletePendingAddress :execrows
DELETE FROM pending_addresses WHERE account_id = $1 AND root = $2;

-- name: RepinContactAddress :execrows
-- The 2.0 pin moves: a renewal at the pinned endpoint or an accepted new
-- address replaces the leaf, its key and the endpoint; the root (the
-- fingerprint column) never moves (PACT sec. 14.3, sec. 5.3).
UPDATE contacts SET endpoint = $1, leaf = $2, leaf_fingerprint = $3, spki = $4, pinned_at = $5 WHERE account_id = $6 AND fingerprint = $7;

-- name: SetContactChainSentKid :execrows
UPDATE contacts SET chain_sent_kid = $1 WHERE account_id = $2 AND fingerprint = $3;

-- name: ClearChainSentKids :execrows
-- After a leaf install every contact must see the new chain once (PACT sec. 13.2).
UPDATE contacts SET chain_sent_kid = '' WHERE account_id = $1;

-- name: SetContactRootCert :execrows
-- Fills in a pin's root certificate the first time a chain carries one: a pin made
-- before this column existed, or one restored from an archive that could not carry it.
-- Never overwrites, because the root a pin names cannot change (PACT sec. 14.3) and the
-- cert already stored is the one that was checked when the pin was made.
UPDATE contacts SET root_cert = $1 WHERE account_id = $2 AND fingerprint = $3 AND (root_cert IS NULL OR length(root_cert) = 0);

-- name: SetLeafRequest :execrows
-- The state a web wallet's answer must carry, as its SHA-256, and the wallet the request went to
-- (migration 0041). Only a pending request carries one.
UPDATE leaves SET request_state_hash = $1, wallet_origin = $2 WHERE account_id = $3 AND kid = $4 AND state = 'pending';

-- name: ConsumeLeafRequest :execrows
-- An answer is accepted once: the check and the consumption are one statement, so two answers
-- carrying the same state cannot both see it.
UPDATE leaves SET request_state_hash = NULL
WHERE account_id = $1 AND kid = $2 AND state = 'pending' AND request_state_hash = $3;

-- name: UpsertVacatedAddress :exec
-- An address an identity has left (migration 0040, PACT sec. 9). The row keeps the latest
-- not_after it has been given: a second vacating of the same endpoint never shortens it.
INSERT INTO vacated_addresses (endpoint, slug, until_at, at) VALUES ($1, $2, $3, $4)
ON CONFLICT (endpoint) DO UPDATE SET slug = excluded.slug, until_at = GREATEST(vacated_addresses.until_at, excluded.until_at), at = excluded.at;

-- name: CountLiveVacatedSlug :one
SELECT COUNT(*) FROM vacated_addresses WHERE slug = $1 AND until_at > $2;

-- name: CountLiveVacatedEndpoint :one
SELECT COUNT(*) FROM vacated_addresses WHERE endpoint = $1 AND until_at > $2;

-- name: ListVacatedAddresses :many
SELECT * FROM vacated_addresses ORDER BY endpoint;

-- name: DeleteExpiredVacatedAddresses :execrows
DELETE FROM vacated_addresses WHERE until_at <= $1;
