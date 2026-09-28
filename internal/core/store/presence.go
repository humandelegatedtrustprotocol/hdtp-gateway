package store

import (
	"context"
	"errors"
)

func (s *SQLite) TouchOwnerPresence(ctx context.Context, at int64) error {
	return s.q.TouchOwnerPresence(ctx, at)
}

func (s *SQLite) OwnerPresenceSeenAt(ctx context.Context) (int64, error) {
	return seenAt(s.q.OwnerPresenceSeenAt(ctx))
}

func (s *Postgres) TouchOwnerPresence(ctx context.Context, at int64) error {
	return s.q.TouchOwnerPresence(ctx, at)
}

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
