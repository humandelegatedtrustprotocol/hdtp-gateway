-- name: InsertOwner :exec
INSERT INTO owners (id, display_name, created_at) VALUES (?, ?, ?);

-- name: GetOwner :one
SELECT * FROM owners WHERE id = ?;

-- name: ListOwners :many
SELECT * FROM owners ORDER BY created_at, id;

-- name: DeleteOwner :execrows
DELETE FROM owners WHERE id = ?;

-- name: InsertAccount :exec
INSERT INTO accounts (id, slug, display_name, algo, created_at) VALUES (?, ?, ?, ?, ?);

-- name: GetAccount :one
SELECT * FROM accounts WHERE id = ?;

-- name: GetAccountBySlug :one
SELECT * FROM accounts WHERE slug = ?;

-- name: ListAccounts :many
SELECT * FROM accounts ORDER BY created_at, id;

-- name: InsertMembership :exec
INSERT INTO memberships (owner_id, account_id, role) VALUES (?, ?, ?);

-- name: ListMembershipsByOwner :many
SELECT * FROM memberships WHERE owner_id = ? ORDER BY account_id;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE owner_id = ? AND account_id = ?;

-- name: InsertCredential :exec
INSERT INTO credentials (id, owner_id, kind, tag, data, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: CountCredentialsByKind :one
SELECT COUNT(*) FROM credentials WHERE kind = ?;

-- name: SetAccountKey :execrows
UPDATE accounts SET fingerprint = ?, key_sealed = ? WHERE id = ? AND fingerprint IS NULL;

-- name: ListCredentialsByKind :many
SELECT * FROM credentials WHERE kind = ? ORDER BY created_at, id;

-- name: InsertSession :exec
INSERT INTO sessions (id, owner_id, created_at, expires_at) VALUES (?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM sessions WHERE id = ?;

-- name: DeleteSession :execrows
DELETE FROM sessions WHERE id = ?;

-- name: InsertToken :exec
INSERT INTO tokens (id, owner_id, label, hash, account_id, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetTokenByHash :one
SELECT * FROM tokens WHERE hash = ?;

-- name: ListTokens :many
SELECT * FROM tokens ORDER BY created_at, id;

-- name: RevokeToken :execrows
UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (seq, ts, account_id, actor_kind, actor_id, action, resource, outcome, request_id, details, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: LastAuditEvent :one
SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1;

-- name: ListAuditEvents :many
SELECT * FROM audit_events ORDER BY seq;

-- name: ListAuditEventsPage :many
-- The portal reads the trail from the present backwards and never needs all of
-- it. ListAuditEvents stays ascending because that is the order the hash chain
-- must be VERIFIED in; this is the reading order: newest first and bounded.
--
-- Both filters are optional and empty means "any". The account filter keeps the
-- node's own rows, which belong to no account: a listener starting or an owner
-- signing in is a fact about the node, not about anybody's identity. account_id
-- is nullable, and a row with no account arrives as NULL, not as ''.
SELECT * FROM audit_events
WHERE (?1 = '' OR actor_id = ?1)
  AND (?2 = '' OR account_id = ?2 OR account_id IS NULL OR account_id = '')
ORDER BY seq DESC LIMIT ?3;

-- name: ListAuditEventsByActor :many
SELECT * FROM audit_events WHERE actor_id = ? ORDER BY seq;

-- name: RotateAccountKey :execrows
UPDATE accounts SET prev_fingerprint = fingerprint, prev_key_sealed = key_sealed,
  fingerprint = ?, key_sealed = ?, grace_until = ?
WHERE id = ? AND fingerprint IS NOT NULL;

-- name: GetAccountPrevKey :one
SELECT prev_fingerprint, prev_key_sealed, grace_until FROM accounts WHERE id = ?;

-- name: ClearAccountPrevKey :execrows
UPDATE accounts SET prev_fingerprint = NULL, prev_key_sealed = NULL, grace_until = 0 WHERE id = ?;

-- name: UpsertRotationFanout :exec
INSERT INTO rotation_fanout (account_id, contact_fpr, new_fpr, status, attempts, last_error, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (account_id, contact_fpr) DO UPDATE SET
  new_fpr = excluded.new_fpr, status = excluded.status, attempts = excluded.attempts,
  last_error = excluded.last_error, updated_at = excluded.updated_at;

-- name: ListRotationFanout :many
SELECT * FROM rotation_fanout WHERE account_id = ? ORDER BY contact_fpr;

-- name: UpdateAccountSeal :execrows
UPDATE accounts SET seal = ? WHERE id = ?;

-- name: ListSettings :many
SELECT * FROM settings ORDER BY key;

-- name: PutSetting :exec
INSERT INTO settings (key, value, secret, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, secret = excluded.secret, updated_at = excluded.updated_at;

-- name: DeleteSetting :exec
DELETE FROM settings WHERE key = ?;

-- name: GetAuditAnchor :one
SELECT * FROM audit_anchor WHERE id = 1;

-- name: SetAuditAnchor :exec
INSERT INTO audit_anchor (id, archived_through_seq, terminal_hash, archive_path, updated_at)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET archived_through_seq = excluded.archived_through_seq,
    terminal_hash = excluded.terminal_hash, archive_path = excluded.archive_path,
    updated_at = excluded.updated_at;

-- name: DeleteAuditEventsThrough :execrows
DELETE FROM audit_events WHERE seq <= ?;

-- DeleteCredentialIfNotLast removes a credential only while another of the same
-- kind survives — the guard that stops the owner locking themselves out. The
-- count and the delete are ONE statement so two concurrent removals cannot both
-- observe "there are two" and both delete.
-- name: DeleteCredentialIfNotLast :execrows
DELETE FROM credentials WHERE id = ? AND kind = ?
  AND (SELECT COUNT(*) FROM credentials WHERE kind = ?) > 1;
