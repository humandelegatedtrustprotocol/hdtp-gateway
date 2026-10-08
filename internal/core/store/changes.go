package store

import (
	"context"
	"fmt"
	"math"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func changeOf(r sqlitedb.Change) Change { return Change(r) }

// pgLimit is a page size as Postgres types LIMIT, int32: one that cannot fit is clamped rather
// than wrapped to a negative one (gosec G115). No real page reaches it.
func pgLimit(n int) int32 {
	if n >= 0 && n <= math.MaxInt32 {
		return int32(n)
	}
	return math.MaxInt32
}

// AppendChange records c in the change log (its ID is ignored) and returns the id assigned. SQLite
// writes one transaction at a time, so ids commit in the order they are assigned.
func (s *SQLite) AppendChange(ctx context.Context, c Change) (int64, error) {
	return s.q.InsertChange(ctx, sqlitedb.InsertChangeParams{AccountID: c.AccountID, Kind: c.Kind,
		ThreadID: c.ThreadID, ContactFpr: c.ContactFpr, Ref: c.Ref, At: c.At})
}

// ChangesAfter returns up to limit changes with ids above after, in id order.
func (s *SQLite) ChangesAfter(ctx context.Context, after int64, limit int) ([]Change, error) {
	rs, err := s.q.ChangesAfter(ctx, sqlitedb.ChangesAfterParams{ID: after, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(rs))
	for _, r := range rs {
		out = append(out, changeOf(r))
	}
	return out, nil
}

// AccountChangesAfter returns up to limit of one account's changes with ids above after, in id
// order.
func (s *SQLite) AccountChangesAfter(ctx context.Context, accountID string, after int64, limit int) ([]Change, error) {
	rs, err := s.q.AccountChangesAfter(ctx, sqlitedb.AccountChangesAfterParams{AccountID: accountID, ID: after, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(rs))
	for _, r := range rs {
		out = append(out, changeOf(r))
	}
	return out, nil
}

// ChangeBounds returns the oldest and newest change ids held, 0 and 0 for an empty log.
func (s *SQLite) ChangeBounds(ctx context.Context) (int64, int64, error) {
	oldest, err := s.q.OldestChangeID(ctx)
	if err != nil {
		return 0, 0, err
	}
	newest, err := s.q.LastChangeID(ctx)
	return oldest, newest, err
}

// DeleteChangesByAccount deletes every change row of one account, for an identity that left.
func (s *SQLite) DeleteChangesByAccount(ctx context.Context, accountID string) (int64, error) {
	return s.q.DeleteChangesByAccount(ctx, accountID)
}

// DeleteChangesBefore deletes the change rows written before at (unix seconds) and returns how many
// went.
func (s *SQLite) DeleteChangesBefore(ctx context.Context, at int64) (int64, error) {
	return s.q.DeleteChangesBefore(ctx, at)
}

// WatchChanges has nothing to watch on SQLite: the poll is the only way a process learns of
// another's changes.
func (s *SQLite) WatchChanges(context.Context, func()) error { return nil }

// AppendChange records c in the change log (its ID is ignored) and returns the id assigned. In one
// transaction it takes the changes advisory lock (LockChanges) so ids commit in the order they are
// assigned, inserts the row, and sends the notification WatchChanges listens for (NotifyChanges),
// which Postgres delivers at commit.
func (s *Postgres) AppendChange(ctx context.Context, c Change) (int64, error) {
	var id int64
	err := s.Atomically(ctx, func(tx Store) error {
		q := tx.(*Postgres).q
		if err := q.LockChanges(ctx); err != nil {
			return err
		}
		var err error
		if id, err = q.InsertChange(ctx, pgdb.InsertChangeParams{AccountID: c.AccountID, Kind: c.Kind,
			ThreadID: c.ThreadID, ContactFpr: c.ContactFpr, Ref: c.Ref, At: c.At}); err != nil {
			return err
		}
		return q.NotifyChanges(ctx)
	})
	return id, err
}

// ChangesAfter returns up to limit changes with ids above after, in id order.
func (s *Postgres) ChangesAfter(ctx context.Context, after int64, limit int) ([]Change, error) {
	rs, err := s.q.ChangesAfter(ctx, pgdb.ChangesAfterParams{ID: after, Limit: pgLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(rs))
	for _, r := range rs {
		out = append(out, Change(r))
	}
	return out, nil
}

// AccountChangesAfter returns up to limit of one account's changes with ids above after, in id
// order.
func (s *Postgres) AccountChangesAfter(ctx context.Context, accountID string, after int64, limit int) ([]Change, error) {
	rs, err := s.q.AccountChangesAfter(ctx, pgdb.AccountChangesAfterParams{AccountID: accountID, ID: after, Limit: pgLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(rs))
	for _, r := range rs {
		out = append(out, Change(r))
	}
	return out, nil
}

// ChangeBounds returns the oldest and newest change ids held, 0 and 0 for an empty log.
func (s *Postgres) ChangeBounds(ctx context.Context) (int64, int64, error) {
	oldest, err := s.q.OldestChangeID(ctx)
	if err != nil {
		return 0, 0, err
	}
	newest, err := s.q.LastChangeID(ctx)
	return oldest, newest, err
}

// DeleteChangesByAccount deletes every change row of one account, for an identity that left.
func (s *Postgres) DeleteChangesByAccount(ctx context.Context, accountID string) (int64, error) {
	return s.q.DeleteChangesByAccount(ctx, accountID)
}

// DeleteChangesBefore deletes the change rows written before at (unix seconds) and returns how many
// went.
func (s *Postgres) DeleteChangesBefore(ctx context.Context, at int64) (int64, error) {
	return s.q.DeleteChangesBefore(ctx, at)
}

// WatchChanges holds one pooled connection LISTENing for AppendChange's notification and wakes on
// each, until ctx ends. The connection is closed rather than returned to the pool: it is still
// listening, and nothing else should receive what it hears.
func (s *Postgres) WatchChanges(ctx context.Context, wake func()) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: watch changes: %w", err)
	}
	defer func() {
		_ = conn.Conn().Close(context.Background())
		conn.Release()
	}()
	if err := pgdb.New(conn).ListenChanges(ctx); err != nil {
		return fmt.Errorf("store: watch changes: %w", err)
	}
	for {
		if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("store: watch changes: %w", err)
		}
		wake()
	}
}
