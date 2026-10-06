package store

import (
	"context"
	"database/sql"
	"fmt"
)

// An identity leaving this host (HDTP §9): the account's rows. identity.Manager.Leave is the one caller that erases, inside Atomically.

func (s *Postgres) DeleteAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *Postgres) DeleteTokensByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteTokensByAccount(ctx, sql.NullString{String: accountID, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *Postgres) DeleteIdempotencyByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteIdempotencyByAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}
