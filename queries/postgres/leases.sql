-- name: TakeLease :one
-- Takes the lease, or renews it for its holder; a lease another holds and has not let expire by
-- the time this one is taken (excluded.taken_at) is left as it is, and no row comes back.
INSERT INTO leases (name, holder, taken_at, expires_at) VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, taken_at = excluded.taken_at, expires_at = excluded.expires_at
WHERE leases.holder = excluded.holder OR leases.expires_at < excluded.taken_at
RETURNING holder;

-- name: ReleaseLease :exec
-- A holder that stops lets its lease go at once, rather than three renewals later.
UPDATE leases SET expires_at = 0 WHERE name = $1 AND holder = $2;
