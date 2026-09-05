package store

import (
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) SyncRelayAllowlist(ctx context.Context, recipientFpr string, senderFprs []string) error {
	if _, err := s.q.ClearRelayAllow(ctx, recipientFpr); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	now := now()
	for _, f := range senderFprs {
		if err := s.q.SyncRelayAllow(ctx, sqlitedb.SyncRelayAllowParams{
			RecipientFpr: recipientFpr, SenderFpr: f, UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

func (s *SQLite) RelayAllowed(ctx context.Context, recipientFpr, senderFpr string) (bool, error) {
	n, err := s.q.RelayAllowed(ctx, sqlitedb.RelayAllowedParams{RecipientFpr: recipientFpr, SenderFpr: senderFpr})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *SQLite) EnqueueRelay(ctx context.Context, item RelayItem) (RelayItem, error) {
	if item.ID == "" {
		item.ID = newID()
	}
	if item.QueuedAt == 0 {
		item.QueuedAt = now()
	}
	err := s.q.EnqueueRelay(ctx, sqlitedb.EnqueueRelayParams{
		ID: item.ID, RecipientFpr: item.RecipientFpr, SenderFpr: item.SenderFpr,
		MsgID: item.MsgID, Envelope: item.Envelope, SizeBytes: item.SizeBytes,
		QueuedAt: item.QueuedAt, ExpiresAt: item.ExpiresAt,
	})
	if err != nil {
		return RelayItem{}, fmt.Errorf("store: %w", err)
	}
	return item, nil
}

func (s *SQLite) FetchRelayQueue(ctx context.Context, recipientFpr string, nowUnix, limit int64) ([]RelayItem, error) {
	rows, err := s.q.FetchRelayQueue(ctx, sqlitedb.FetchRelayQueueParams{
		RecipientFpr: recipientFpr, ExpiresAt: nowUnix, Limit: limit,
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

func (s *SQLite) CountRelayQueue(ctx context.Context, recipientFpr string, nowUnix int64) (int64, error) {
	n, err := s.q.CountRelayQueue(ctx, sqlitedb.CountRelayQueueParams{RecipientFpr: recipientFpr, ExpiresAt: nowUnix})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) AckRelay(ctx context.Context, id, recipientFpr string) (bool, error) {
	n, err := s.q.AckRelay(ctx, sqlitedb.AckRelayParams{ID: id, RecipientFpr: recipientFpr})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *SQLite) PurgeExpiredRelay(ctx context.Context, nowUnix int64) (int64, error) {
	n, err := s.q.PurgeExpiredRelay(ctx, nowUnix)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) RelayQueueUsage(ctx context.Context, recipientFpr string, nowUnix int64) (int64, int64, error) {
	r, err := s.q.RelayQueueUsage(ctx, sqlitedb.RelayQueueUsageParams{RecipientFpr: recipientFpr, ExpiresAt: nowUnix})
	if err != nil {
		return 0, 0, fmt.Errorf("store: %w", err)
	}
	return r.Items, sumToInt64(r.Bytes), nil
}

// sumToInt64 unwraps a COALESCE(SUM(...)) scan, which the driver hands back as
// int64 or float64 depending on the engine — the SumBlobBytes precedent.
func sumToInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}
