package store

import (
	"context"
	"fmt"
	"math"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (s *Postgres) SyncRelayAllowlist(ctx context.Context, recipientFpr string, senderFprs []string) error {
	if _, err := s.q.ClearRelayAllow(ctx, recipientFpr); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	now := now()
	for _, f := range senderFprs {
		if err := s.q.SyncRelayAllow(ctx, pgdb.SyncRelayAllowParams{
			RecipientFpr: recipientFpr, SenderFpr: f, UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

func (s *Postgres) RelayAllowed(ctx context.Context, recipientFpr, senderFpr string) (bool, error) {
	n, err := s.q.RelayAllowed(ctx, pgdb.RelayAllowedParams{RecipientFpr: recipientFpr, SenderFpr: senderFpr})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *Postgres) EnqueueRelay(ctx context.Context, item RelayItem) (RelayItem, error) {
	if item.ID == "" {
		item.ID = newID()
	}
	if item.QueuedAt == 0 {
		item.QueuedAt = now()
	}
	err := s.q.EnqueueRelay(ctx, pgdb.EnqueueRelayParams{
		ID: item.ID, RecipientFpr: item.RecipientFpr, SenderFpr: item.SenderFpr,
		MsgID: item.MsgID, Envelope: item.Envelope, SizeBytes: item.SizeBytes,
		QueuedAt: item.QueuedAt, ExpiresAt: item.ExpiresAt,
	})
	if err != nil {
		return RelayItem{}, fmt.Errorf("store: %w", err)
	}
	return item, nil
}

func (s *Postgres) FetchRelayQueue(ctx context.Context, recipientFpr string, nowUnix, limit int64) ([]RelayItem, error) {
	// Postgres takes the limit as int32; a wider value would truncate silently,
	// and a truncation that lands negative is a nonsense LIMIT rather than an error.
	if limit < 0 {
		limit = 0
	}
	if limit > math.MaxInt32 {
		limit = math.MaxInt32
	}
	rows, err := s.q.FetchRelayQueue(ctx, pgdb.FetchRelayQueueParams{
		// #nosec G115 -- clamped to [0, MaxInt32] immediately above
		RecipientFpr: recipientFpr, ExpiresAt: nowUnix, Limit: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]RelayItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, RelayItem{ID: r.ID, RecipientFpr: r.RecipientFpr, SenderFpr: r.SenderFpr,
			MsgID: r.MsgID, Envelope: r.Envelope, SizeBytes: r.SizeBytes, QueuedAt: r.QueuedAt, ExpiresAt: r.ExpiresAt})
	}
	return out, nil
}

func (s *Postgres) CountRelayQueue(ctx context.Context, recipientFpr string, nowUnix int64) (int64, error) {
	n, err := s.q.CountRelayQueue(ctx, pgdb.CountRelayQueueParams{RecipientFpr: recipientFpr, ExpiresAt: nowUnix})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *Postgres) AckRelay(ctx context.Context, id, recipientFpr string) (bool, error) {
	n, err := s.q.AckRelay(ctx, pgdb.AckRelayParams{ID: id, RecipientFpr: recipientFpr})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *Postgres) PurgeExpiredRelay(ctx context.Context, nowUnix int64) (int64, error) {
	n, err := s.q.PurgeExpiredRelay(ctx, nowUnix)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (p *Postgres) RelayQueueUsage(ctx context.Context, recipientFpr string, nowUnix int64) (int64, int64, error) {
	r, err := p.q.RelayQueueUsage(ctx, pgdb.RelayQueueUsageParams{RecipientFpr: recipientFpr, ExpiresAt: nowUnix})
	if err != nil {
		return 0, 0, fmt.Errorf("store: %w", err)
	}
	return r.Items, sumToInt64(r.Bytes), nil
}
