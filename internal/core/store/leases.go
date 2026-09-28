package store

import (
	"context"
	"errors"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
	"github.com/pact-cloud/pact-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) TakeLease(ctx context.Context, name, holder string, now, until int64) (bool, error) {
	return took(holder)(s.q.TakeLease(ctx, sqlitedb.TakeLeaseParams{Name: name, Holder: holder, TakenAt: now, ExpiresAt: until}))
}

func (s *Postgres) TakeLease(ctx context.Context, name, holder string, now, until int64) (bool, error) {
	return took(holder)(s.q.TakeLease(ctx, pgdb.TakeLeaseParams{Name: name, Holder: holder, TakenAt: now, ExpiresAt: until}))
}

func (s *SQLite) ReleaseLease(ctx context.Context, name, holder string) error {
	return s.q.ReleaseLease(ctx, sqlitedb.ReleaseLeaseParams{Name: name, Holder: holder})
}

func (s *Postgres) ReleaseLease(ctx context.Context, name, holder string) error {
	return s.q.ReleaseLease(ctx, pgdb.ReleaseLeaseParams{Name: name, Holder: holder})
}

// took reads TakeLease's answer: the holder's name back when it holds the lease, no row when
// another does.
func took(holder string) func(string, error) (bool, error) {
	return func(got string, err error) (bool, error) {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return err == nil && got == holder, err
	}
}
