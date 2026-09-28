-- name: TouchOwnerPresence :exec
INSERT INTO owner_presence (id, seen_at) VALUES (1, $1)
ON CONFLICT (id) DO UPDATE SET seen_at = excluded.seen_at;

-- name: OwnerPresenceSeenAt :one
SELECT seen_at FROM owner_presence WHERE id = 1;
