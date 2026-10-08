package store

import (
	"context"
	"database/sql"
	"fmt"
)

// An identity leaving this host (HDTP §9): the account's rows. identity.Manager.Leave is the one caller that erases, inside Atomically.

// DeleteAccount deletes the account row, and with it every row that names it by a foreign key (ON
// DELETE CASCADE), and returns how many account rows went. It is one step of identity.Manager.Leave,
// which calls it inside Atomically.
func (s *Postgres) DeleteAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

// DeleteTokensByAccount deletes, rather than revokes, the tokens scoped to the account, so no row
// goes on naming an identity that left.
func (s *Postgres) DeleteTokensByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteTokensByAccount(ctx, sql.NullString{String: accountID, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

// DeleteIdempotencyByAccount deletes the account's idempotency records, which have no foreign key to
// cascade from.
func (s *Postgres) DeleteIdempotencyByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteIdempotencyByAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}
