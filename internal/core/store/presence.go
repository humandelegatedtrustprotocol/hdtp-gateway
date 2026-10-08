package store

import (
	"context"
	"errors"
)

// TouchOwnerPresence records that the owner's agent asked at the given time.
func (s *SQLite) TouchOwnerPresence(ctx context.Context, at int64) error {
	return s.q.TouchOwnerPresence(ctx, at)
}

// OwnerPresenceSeenAt returns when the owner's agent last asked, 0 if it never has.
func (s *SQLite) OwnerPresenceSeenAt(ctx context.Context) (int64, error) {
	return seenAt(s.q.OwnerPresenceSeenAt(ctx))
}

// TouchOwnerPresence records that the owner's agent asked at the given time.
func (s *Postgres) TouchOwnerPresence(ctx context.Context, at int64) error {
	return s.q.TouchOwnerPresence(ctx, at)
}

// OwnerPresenceSeenAt returns when the owner's agent last asked, 0 if it never has.
func (s *Postgres) OwnerPresenceSeenAt(ctx context.Context) (int64, error) {
	return seenAt(s.q.OwnerPresenceSeenAt(ctx))
}

// seenAt reads "never" as 0.
func seenAt(at int64, err error) (int64, error) {
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	return at, err
}
