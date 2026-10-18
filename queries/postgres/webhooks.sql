-- Outbound webhooks (internal/services/webhooks). Every statement is scoped to the account the
-- caller acts for: an endpoint id alone would let an owner of one account touch another's.

-- name: InsertWebhookEndpoint :exec
INSERT INTO webhook_endpoints (id, account_id, url, events, status, failures, secret_sealed, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'active', 0, $5, $6, $7);

-- name: ListWebhookEndpoints :many
SELECT * FROM webhook_endpoints WHERE account_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2;

-- name: GetWebhookEndpoint :one
SELECT * FROM webhook_endpoints WHERE account_id = $1 AND id = $2;

-- name: RotateWebhookSecret :execrows
-- The secret being replaced becomes the previous one, so a rotation during a rotation drops the
-- oldest of three.
UPDATE webhook_endpoints SET previous_sealed = secret_sealed, secret_sealed = $1, previous_until = $2, updated_at = $3
WHERE account_id = $4 AND id = $5;

-- name: PauseWebhookEndpoint :execrows
UPDATE webhook_endpoints SET status = 'paused', updated_at = $1 WHERE account_id = $2 AND id = $3;

-- name: ResumeWebhookEndpoint :execrows
-- Resuming clears the failure run: an endpoint parked for being down and since fixed is not one
-- failure from being parked again.
UPDATE webhook_endpoints SET status = 'active', failures = 0, updated_at = $1 WHERE account_id = $2 AND id = $3;

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE account_id = $1 AND id = $2;

-- name: InsertWebhookDelivery :exec
INSERT INTO webhook_deliveries (id, account_id, endpoint_id, event_id, event_type, status, http_status, latency_ms, excerpt, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ClearWebhookFailures :execrows
UPDATE webhook_endpoints SET failures = 0, updated_at = $1 WHERE account_id = $2 AND id = $3;

-- name: CountWebhookFailure :execrows
-- One more failure in a row; the one that reaches the limit parks the endpoint. SET reads the
-- row as it was, so the argument is the run before this failure that parks it: the limit less one.
UPDATE webhook_endpoints SET failures = failures + 1,
    status = CASE WHEN failures >= $1 THEN 'paused' ELSE status END,
    updated_at = $2
WHERE account_id = $3 AND id = $4;

-- name: ListWebhookDeliveries :many
SELECT * FROM webhook_deliveries WHERE account_id = $1 AND endpoint_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3;

-- name: ListWebhookAccounts :many
-- The accounts the dispatcher reads the change log of: every one with an endpoint, active or
-- paused, so a paused endpoint's cursor keeps moving and it is not sent the backlog on resume.
SELECT DISTINCT account_id FROM webhook_endpoints ORDER BY account_id;

-- name: GetWebhookCursor :one
SELECT last_change_id FROM webhook_cursor WHERE account_id = $1;

-- name: StartWebhookCursor :execrows
-- An account's first claim; no row changes when another process made it first.
INSERT INTO webhook_cursor (account_id, last_change_id) VALUES ($1, $2)
ON CONFLICT (account_id) DO NOTHING;

-- name: MoveWebhookCursor :execrows
-- Every later claim moves the cursor only from the id the claimant read; no row changes when
-- another process moved it first.
UPDATE webhook_cursor SET last_change_id = $1 WHERE account_id = $2 AND last_change_id = $3;
