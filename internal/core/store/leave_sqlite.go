package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// An identity leaving this host (HDTP §9): the account's rows and the addresses it
// leaves reserved. identity.Manager.Leave is the one caller that erases, inside Atomically.

func (s *SQLite) DeleteAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) DeleteTokensByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteTokensByAccount(ctx, sql.NullString{String: accountID, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) DeleteIdempotencyByAccount(ctx context.Context, accountID string) (int64, error) {
	n, err := s.q.DeleteIdempotencyByAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) UpsertVacatedAddress(ctx context.Context, v VacatedAddress) error {
	if v.At == 0 {
		v.At = now()
	}
	if err := s.q.UpsertVacatedAddress(ctx, sqlitedb.UpsertVacatedAddressParams{Endpoint: v.Endpoint, Slug: v.Slug, UntilAt: v.UntilAt, At: v.At}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *SQLite) LiveVacatedSlug(ctx context.Context, slug string, at int64) (bool, error) {
	n, err := s.q.CountLiveVacatedSlug(ctx, sqlitedb.CountLiveVacatedSlugParams{Slug: slug, UntilAt: at})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *SQLite) LiveVacatedEndpoint(ctx context.Context, endpoint string, at int64) (bool, error) {
	n, err := s.q.CountLiveVacatedEndpoint(ctx, sqlitedb.CountLiveVacatedEndpointParams{Endpoint: endpoint, UntilAt: at})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *SQLite) ListVacatedAddresses(ctx context.Context) ([]VacatedAddress, error) {
	rows, err := s.q.ListVacatedAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]VacatedAddress, 0, len(rows))
	for _, r := range rows {
		out = append(out, VacatedAddress(r))
	}
	return out, nil
}

func (s *SQLite) DeleteExpiredVacatedAddresses(ctx context.Context, at int64) (int64, error) {
	n, err := s.q.DeleteExpiredVacatedAddresses(ctx, at)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}
