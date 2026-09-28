-- name: InsertOwner :exec
INSERT INTO owners (id, display_name, created_at) VALUES ($1, $2, $3);

-- name: GetOwner :one
SELECT * FROM owners WHERE id = $1;

-- name: ListOwners :many
SELECT * FROM owners ORDER BY created_at, id;

-- name: DeleteOwner :execrows
DELETE FROM owners WHERE id = $1;

-- name: InsertAccount :exec
INSERT INTO accounts (id, slug, display_name, algo, created_at) VALUES ($1, $2, $3, $4, $5);

-- name: GetAccount :one
SELECT * FROM accounts WHERE id = $1;

-- name: GetAccountBySlug :one
SELECT * FROM accounts WHERE slug = $1;

-- name: ListAccounts :many
SELECT * FROM accounts ORDER BY created_at, id;

-- name: InsertMembership :exec
INSERT INTO memberships (owner_id, account_id, role) VALUES ($1, $2, $3);

-- name: ListMembershipsByOwner :many
SELECT * FROM memberships WHERE owner_id = $1 ORDER BY account_id;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE owner_id = $1 AND account_id = $2;

-- name: InsertCredential :exec
INSERT INTO credentials (id, owner_id, kind, tag, data, created_at) VALUES ($1, $2, $3, $4, $5, $6);

-- name: CountCredentialsByKind :one
SELECT COUNT(*) FROM credentials WHERE kind = $1;

-- name: SetAccountKey :execrows
UPDATE accounts SET fingerprint = $1, key_sealed = $2 WHERE id = $3 AND fingerprint IS NULL;

-- name: ListCredentialsByKind :many
SELECT * FROM credentials WHERE kind = $1 ORDER BY created_at, id;

-- name: InsertSession :exec
INSERT INTO sessions (id, owner_id, created_at, expires_at) VALUES ($1, $2, $3, $4);

-- name: GetSession :one
SELECT * FROM sessions WHERE id = $1;

-- name: DeleteSession :execrows
DELETE FROM sessions WHERE id = $1;

-- name: DeleteExpiredSessions :execrows
-- A session is deleted at sign-out, or when it is presented after its time. One that is simply
-- abandoned is never presented again, so the hourly sweep is what removes it.
DELETE FROM sessions WHERE expires_at <= $1;

-- name: InsertToken :exec
INSERT INTO tokens (id, owner_id, label, hash, account_id, created_at) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetTokenByHash :one
SELECT * FROM tokens WHERE hash = $1;

-- name: ListTokens :many
SELECT * FROM tokens ORDER BY created_at, id;

-- name: RevokeToken :execrows
UPDATE tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (seq, ts, account_id, actor_kind, actor_id, action, resource, outcome, request_id, details, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: LastAuditEvent :one
SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1;

-- name: ListAuditEvents :many
SELECT * FROM audit_events ORDER BY seq;

-- name: ListAuditEventsPage :many
-- The portal reads the trail from the present backwards and never needs all of
-- it. ListAuditEvents stays ascending because that is the order the hash chain
-- must be VERIFIED in; this is the reading order: newest first and bounded.
--
-- The account filter is optional and empty means "any". It keeps the node's own
-- rows, which belong to no account: a listener starting or an owner signing in is
-- a fact about the node, not about anybody's identity. account_id is nullable, and
-- a row with no account arrives as NULL, not as ''. That is also why this walk is
-- short whatever the account: the node's own rows match every filter.
SELECT * FROM audit_events
WHERE ($1 = '' OR account_id = $1 OR account_id IS NULL OR account_id = '')
ORDER BY seq DESC LIMIT $2;

-- name: ListAuditEventsPageByActor :many
-- One actor's page. It is its own statement so that it is answered from
-- `audit_events_actor`, read backwards. As `(? = '' OR actor_id = ?)` inside the
-- statement above it could not be, and an actor with thirty rows in a million cost
-- a walk of the whole chain to find them.
SELECT * FROM audit_events
WHERE actor_id = $1
  AND ($2 = '' OR account_id = $2 OR account_id IS NULL OR account_id = '')
ORDER BY seq DESC LIMIT $3;

-- name: ListAuditEventsByActor :many
SELECT * FROM audit_events WHERE actor_id = $1 ORDER BY seq;

-- name: UpsertMoveFanout :exec
INSERT INTO move_fanout (account_id, contact_fpr, leaf_kid, status, attempts, last_error, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (account_id, contact_fpr) DO UPDATE SET
  leaf_kid = excluded.leaf_kid, status = excluded.status, attempts = excluded.attempts,
  last_error = excluded.last_error, updated_at = excluded.updated_at;

-- name: ListMoveFanout :many
SELECT * FROM move_fanout WHERE account_id = $1 ORDER BY contact_fpr;

-- name: UpdateAccountSeal :execrows
UPDATE accounts SET seal = $1 WHERE id = $2;

-- name: ListSettings :many
SELECT * FROM settings ORDER BY key;

-- name: PutSetting :exec
INSERT INTO settings (key, value, secret, updated_at) VALUES ($1, $2, $3, $4)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, secret = excluded.secret, updated_at = excluded.updated_at;

-- name: DeleteSetting :exec
DELETE FROM settings WHERE key = $1;

-- name: GetAuditAnchor :one
SELECT * FROM audit_anchor WHERE id = 1;

-- name: SetAuditAnchor :exec
INSERT INTO audit_anchor (id, archived_through_seq, terminal_hash, archive_path, updated_at)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT(id) DO UPDATE SET archived_through_seq = excluded.archived_through_seq,
    terminal_hash = excluded.terminal_hash, archive_path = excluded.archive_path,
    updated_at = excluded.updated_at;

-- name: DeleteAuditEventsThrough :execrows
DELETE FROM audit_events WHERE seq <= $1;

-- name: ListDueLeaves :many
-- The identities that left this node before a cutoff (SPEC sec. 3.11): the account_leave rows
-- whose erase went through (ok, or partial when media files were left on disk), oldest first.
-- A refused or failed leave erased nothing, so it is not a departure. Answered from the partial
-- index audit_events_leaves.
SELECT * FROM audit_events
WHERE action = 'account_leave' AND outcome IN ('ok', 'partial') AND ts <= $1
ORDER BY seq LIMIT $2;

-- name: InsertAuditArchiveRow :exec
-- One row an identity's archive wrote and verified: the prune guard lets exactly this seq, with
-- exactly this hash, be deleted (migration 0045). Only Store.ArchiveAuditRows writes it, inside
-- the transaction that deletes the row and empties this table again.
INSERT INTO audit_archive_rows (seq, hash) VALUES ($1, $2);

-- name: DeleteArchivedAuditEvent :execrows
-- One row an archive holds. The prune guard admits it only while audit_archive_rows lists its seq
-- with its hash.
DELETE FROM audit_events WHERE seq = $1;

-- name: ClearAuditArchiveRows :exec
DELETE FROM audit_archive_rows;

-- DeleteCredentialIfNotLast removes a credential only while another of the same
-- kind survives - the guard that stops the owner locking themselves out.
-- FOR UPDATE over the kind's rows makes the guard atomic: an uncorrelated
-- COUNT is an InitPlan evaluated once against the statement's own snapshot, so
-- under READ COMMITTED two concurrent removals could each see two and each
-- delete one, leaving zero.
-- name: DeleteCredentialIfNotLast :execrows
WITH held AS (
  SELECT id FROM credentials WHERE kind = $2 ORDER BY id FOR UPDATE
)
DELETE FROM credentials WHERE credentials.id = $1 AND credentials.kind = $2
  AND (SELECT COUNT(*) FROM held) > 1;

-- name: DeleteAccount :execrows
-- An identity leaving this host (PACT sec. 9): every table that names the account by a foreign
-- key goes with it (ON DELETE CASCADE). The ones that name it without one (tokens, idempotency,
-- the per-account settings) are deleted first, in the same transaction (identity.Manager.Leave).
DELETE FROM accounts WHERE id = $1;

-- name: DeleteTokensByAccount :execrows
-- A token scoped to an identity that has left acts for nobody. Deleted, not revoked: a revoked
-- row would go on naming the account.
DELETE FROM tokens WHERE account_id = $1;

-- name: LockAccountRow :exec
-- Holds one account's row until the transaction ends, so two transactions that change the same
-- account's ledger run one after the other (a signing request replacing the pending one). SQLite
-- needs no statement for it: every transaction there takes the write lock at BEGIN.
SELECT id FROM accounts WHERE id = $1 FOR UPDATE;

-- name: LockSlug :exec
-- A transaction-scoped lock on one slug: creating an account under it and reserving it for an
-- identity that left (vacated_addresses) take it, so the one that comes second reads what the
-- first wrote. Released at commit or rollback.
SELECT pg_advisory_xact_lock(hashtext($1));
