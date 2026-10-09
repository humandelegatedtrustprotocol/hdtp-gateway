-- name: InsertIntegration :exec
INSERT INTO integrations (id, account_id, slug, transport, endpoint, command, auth_kind, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetIntegration :one
SELECT * FROM integrations WHERE account_id = ? AND slug = ?;

-- name: GetIntegrationByID :one
SELECT * FROM integrations WHERE id = ?;

-- name: GetAccountIntegration :one
SELECT * FROM integrations WHERE account_id = ? AND id = ?;

-- name: ListIntegrations :many
SELECT * FROM integrations WHERE account_id = ? ORDER BY slug;

-- name: UpdateIntegrationStatus :execrows
UPDATE integrations SET status = ?, updated_at = ? WHERE id = ?;

-- name: UpdateIntegrationConfig :execrows
UPDATE integrations SET transport = ?, endpoint = ?, command = ?, auth_kind = ?, updated_at = ? WHERE id = ?;

-- name: DeleteIntegration :execrows
DELETE FROM integrations WHERE id = ?;

-- name: SetIntegrationSecret :execrows
UPDATE integrations SET secret = ?, updated_at = ? WHERE id = ?;

-- name: GetIntegrationSecret :one
SELECT secret FROM integrations WHERE id = ?;

-- name: InsertCatalog :exec
INSERT INTO catalogs (id, integration_id, version, tools, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: LatestCatalog :one
SELECT * FROM catalogs WHERE integration_id = ? ORDER BY version DESC LIMIT 1;

-- name: GetCatalog :one
SELECT * FROM catalogs WHERE integration_id = ? AND version = ?;

-- name: InsertExposure :exec
INSERT INTO exposures (id, integration_id, version, catalog_version, entries, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: LatestExposure :one
SELECT * FROM exposures WHERE integration_id = ? ORDER BY version DESC LIMIT 1;

-- name: GetExposure :one
SELECT * FROM exposures WHERE integration_id = ? AND version = ?;

-- name: InsertIdempotency :execrows
INSERT INTO idempotency (account_id, contact_fpr, msg_id, ack, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING;

-- name: GetIdempotency :one
SELECT ack FROM idempotency WHERE account_id = ? AND contact_fpr = ? AND msg_id = ?;

-- name: UpdateIdempotencyAck :execrows
UPDATE idempotency SET ack = ? WHERE account_id = ? AND contact_fpr = ? AND msg_id = ?;

-- name: DeleteExpiredIdempotency :execrows
-- A record past its window protects nothing (HDTP sec. 13.3): nothing later than the window passes
-- the freshness check, so a replay of that envelope is refused before this table is asked.
DELETE FROM idempotency WHERE expires_at <= ?;

-- name: DeleteUndatedIdempotencyBefore :execrows
-- A record written without a window (a `book_slot` replay guard) is kept thirty days (SPEC 11).
DELETE FROM idempotency WHERE expires_at IS NULL AND created_at <= ?;

-- name: DeleteIdempotencyByAccount :execrows
-- The records of an identity that has left this host (HDTP sec. 9): the table has no foreign key.
DELETE FROM idempotency WHERE account_id = ?;

-- name: InsertPendingRequest :exec
INSERT INTO pending_requests (id, account_id, contact_fpr, capability, args, trust_flag, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPendingRequest :one
SELECT * FROM pending_requests WHERE id = ?;

-- name: GetAccountPendingRequest :one
SELECT * FROM pending_requests WHERE account_id = ? AND id = ?;

-- name: ListOpenPendingRequests :many
SELECT * FROM pending_requests WHERE account_id = ? AND status = 'open' AND expires_at > ? ORDER BY created_at, id;

-- name: AnswerPendingRequest :execrows
UPDATE pending_requests SET status = 'answered', result = ?, answered_at = ?
WHERE account_id = ? AND id = ? AND status = 'open' AND expires_at > ?;
