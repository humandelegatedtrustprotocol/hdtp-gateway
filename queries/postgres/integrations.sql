-- name: InsertIntegration :exec
INSERT INTO integrations (id, account_id, slug, transport, endpoint, command, auth_kind, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetIntegration :one
SELECT * FROM integrations WHERE account_id = $1 AND slug = $2;

-- name: GetIntegrationByID :one
SELECT * FROM integrations WHERE id = $1;

-- name: ListIntegrations :many
SELECT * FROM integrations WHERE account_id = $1 ORDER BY slug;

-- name: UpdateIntegrationStatus :execrows
UPDATE integrations SET status = $1, updated_at = $2 WHERE id = $3;

-- name: UpdateIntegrationConfig :execrows
UPDATE integrations SET transport = $1, endpoint = $2, command = $3, auth_kind = $4, updated_at = $5 WHERE id = $6;

-- name: DeleteIntegration :execrows
DELETE FROM integrations WHERE id = $1;

-- name: SetIntegrationSecret :execrows
UPDATE integrations SET secret = $1, updated_at = $2 WHERE id = $3;

-- name: GetIntegrationSecret :one
SELECT secret FROM integrations WHERE id = $1;

-- name: InsertCatalog :exec
INSERT INTO catalogs (id, integration_id, version, tools, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: LatestCatalog :one
SELECT * FROM catalogs WHERE integration_id = $1 ORDER BY version DESC LIMIT 1;

-- name: GetCatalog :one
SELECT * FROM catalogs WHERE integration_id = $1 AND version = $2;

-- name: InsertExposure :exec
INSERT INTO exposures (id, integration_id, version, catalog_version, entries, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: LatestExposure :one
SELECT * FROM exposures WHERE integration_id = $1 ORDER BY version DESC LIMIT 1;

-- name: GetExposure :one
SELECT * FROM exposures WHERE integration_id = $1 AND version = $2;

-- name: InsertIdempotency :execrows
INSERT INTO idempotency (account_id, contact_fpr, msg_id, ack, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING;

-- name: GetIdempotency :one
SELECT ack FROM idempotency WHERE account_id = $1 AND contact_fpr = $2 AND msg_id = $3;

-- name: UpdateIdempotencyAck :execrows
UPDATE idempotency SET ack = $1 WHERE account_id = $2 AND contact_fpr = $3 AND msg_id = $4;

-- name: DeleteExpiredIdempotency :execrows
-- A record past its window protects nothing (HDTP sec. 13.3): nothing later than the window passes
-- the freshness check, so a replay of that envelope is refused before this table is asked.
DELETE FROM idempotency WHERE expires_at <= $1;

-- name: DeleteUndatedIdempotencyBefore :execrows
-- A record written without a window (a `book_slot` replay guard) is kept thirty days (SPEC 11).
DELETE FROM idempotency WHERE expires_at IS NULL AND created_at <= $1;

-- name: DeleteIdempotencyByAccount :execrows
-- The records of an identity that has left this host (HDTP sec. 9): the table has no foreign key.
DELETE FROM idempotency WHERE account_id = $1;

-- name: InsertPendingRequest :exec
INSERT INTO pending_requests (id, account_id, contact_fpr, capability, args, trust_flag, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetPendingRequest :one
SELECT * FROM pending_requests WHERE id = $1;

-- name: ListOpenPendingRequests :many
SELECT * FROM pending_requests WHERE account_id = $1 AND status = 'open' AND expires_at > $2 ORDER BY created_at, id;

-- name: AnswerPendingRequest :execrows
UPDATE pending_requests SET status = 'answered', result = $1, answered_at = $2
WHERE id = $3 AND status = 'open' AND expires_at > $4;
