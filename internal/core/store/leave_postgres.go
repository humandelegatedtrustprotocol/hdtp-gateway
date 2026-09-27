package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
)

// An identity leaving this host (PACT §9; migration 0040): the account's rows and the addresses it
// leaves reserved. identity.Manager.Leave is the one caller that erases, inside Atomically.

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

func (s *Postgres) UpsertVacatedAddress(ctx context.Context, v VacatedAddress) error {
	if v.At == 0 {
		v.At = now()
	}
	// The slug's lock (LockSlug): a create of the same slug waits for this transaction and then
	// reads the reservation. Inside Atomically, as identity.Manager.Leave calls it; outside one the
	// lock is released as the statement ends and orders nothing.
	if err := s.q.LockSlug(ctx, v.Slug); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := s.q.UpsertVacatedAddress(ctx, pgdb.UpsertVacatedAddressParams{Endpoint: v.Endpoint, Slug: v.Slug, UntilAt: v.UntilAt, At: v.At}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *Postgres) LiveVacatedSlug(ctx context.Context, slug string, at int64) (bool, error) {
	n, err := s.q.CountLiveVacatedSlug(ctx, pgdb.CountLiveVacatedSlugParams{Slug: slug, UntilAt: at})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *Postgres) LiveVacatedEndpoint(ctx context.Context, endpoint string, at int64) (bool, error) {
	n, err := s.q.CountLiveVacatedEndpoint(ctx, pgdb.CountLiveVacatedEndpointParams{Endpoint: endpoint, UntilAt: at})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *Postgres) ListVacatedAddresses(ctx context.Context) ([]VacatedAddress, error) {
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

func (s *Postgres) DeleteExpiredVacatedAddresses(ctx context.Context, at int64) (int64, error) {
	n, err := s.q.DeleteExpiredVacatedAddresses(ctx, at)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}
