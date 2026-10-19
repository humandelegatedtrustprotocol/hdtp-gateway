package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertOwnerAsk writes a; false, writing nothing, when a unique key already holds it.
func (s *SQLite) InsertOwnerAsk(ctx context.Context, a OwnerAsk) (bool, error) {
	n, err := s.q.InsertOwnerAsk(ctx, ownerAskInsert(a))
	return n == 1, err
}

// GetOwnerAsk returns one of the account's asks or notices, or ErrNotFound.
func (s *SQLite) GetOwnerAsk(ctx context.Context, accountID, id string) (OwnerAsk, error) {
	r, err := s.q.GetOwnerAsk(ctx, sqlitedb.GetOwnerAskParams{AccountID: accountID, ID: id})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(r), nil
}

// GetOwnerAskFor returns the ask or notice of that kind about that message, or ErrNotFound.
func (s *SQLite) GetOwnerAskFor(ctx context.Context, accountID, kind, threadID, forMsgID string) (OwnerAsk, error) {
	r, err := s.q.GetOwnerAskFor(ctx, sqlitedb.GetOwnerAskForParams{AccountID: accountID, Kind: kind, ThreadID: threadID, ForMsgID: forMsgID})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(r), nil
}

// GetOpenOwnerAsk returns the thread's open ask, or ErrNotFound.
func (s *SQLite) GetOpenOwnerAsk(ctx context.Context, accountID, threadID string) (OwnerAsk, error) {
	r, err := s.q.GetOpenOwnerAsk(ctx, sqlitedb.GetOpenOwnerAskParams{AccountID: accountID, ThreadID: threadID})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(r), nil
}

// ListOwnerAsks returns up to limit of the account's asks and notices, newest first.
func (s *SQLite) ListOwnerAsks(ctx context.Context, accountID string, limit int) ([]OwnerAsk, error) {
	return ownerAsks(s.q.ListOwnerAsks(ctx, sqlitedb.ListOwnerAsksParams{AccountID: accountID, Limit: int64(limit)}))
}

// ListOpenOwnerAsks returns up to limit of the account's open asks, newest first.
func (s *SQLite) ListOpenOwnerAsks(ctx context.Context, accountID string, limit int) ([]OwnerAsk, error) {
	return ownerAsks(s.q.ListOpenOwnerAsks(ctx, sqlitedb.ListOpenOwnerAsksParams{AccountID: accountID, Limit: int64(limit)}))
}

// ListThreadOwnerAsks returns up to limit asks and notices of one thread, newest first.
func (s *SQLite) ListThreadOwnerAsks(ctx context.Context, accountID, threadID string, limit int) ([]OwnerAsk, error) {
	return ownerAsks(s.q.ListThreadOwnerAsks(ctx, sqlitedb.ListThreadOwnerAsksParams{AccountID: accountID, ThreadID: threadID, Limit: int64(limit)}))
}

// ListContactOwnerAsks returns up to limit asks and notices of the threads with one contact, newest
// first.
func (s *SQLite) ListContactOwnerAsks(ctx context.Context, accountID, contactFpr string, limit int) ([]OwnerAsk, error) {
	return ownerAsks(s.q.ListContactOwnerAsks(ctx, sqlitedb.ListContactOwnerAsksParams{AccountID: accountID, ContactFpr: contactFpr, Limit: int64(limit)}))
}

// CountOpenOwnerAsks counts the account's open asks that have not expired by now.
func (s *SQLite) CountOpenOwnerAsks(ctx context.Context, accountID string, now int64) (int64, error) {
	return s.q.CountOpenOwnerAsks(ctx, sqlitedb.CountOpenOwnerAsksParams{AccountID: accountID, ExpiresAt: now})
}

// CloseOwnerAsk moves an open, unexpired ask to status with the answer line; false for any other.
func (s *SQLite) CloseOwnerAsk(ctx context.Context, accountID, id, status, answer string, now int64) (bool, error) {
	n, err := s.q.CloseOwnerAsk(ctx, sqlitedb.CloseOwnerAskParams{Status: status, AnswerText: answer, UpdatedAt: now, AccountID: accountID, ID: id, ExpiresAt: now})
	return n == 1, err
}

// ExpireOwnerAsk moves an open ask whose time has come to expired; false for any other.
func (s *SQLite) ExpireOwnerAsk(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ExpireOwnerAsk(ctx, sqlitedb.ExpireOwnerAskParams{UpdatedAt: now, AccountID: accountID, ID: id, ExpiresAt: now})
	return n == 1, err
}

// ListDueOwnerAsks returns up to limit open asks, of every account, whose time has come.
func (s *SQLite) ListDueOwnerAsks(ctx context.Context, now int64, limit int) ([]OwnerAsk, error) {
	return ownerAsks(s.q.ListDueOwnerAsks(ctx, sqlitedb.ListDueOwnerAsksParams{ExpiresAt: now, Limit: int64(limit)}))
}

// DeleteThreadOwnerAsks deletes one thread's asks and notices and returns how many went.
func (s *SQLite) DeleteThreadOwnerAsks(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.DeleteThreadOwnerAsks(ctx, sqlitedb.DeleteThreadOwnerAsksParams{AccountID: accountID, ThreadID: threadID})
}

// DeleteOrphanOwnerAsks deletes the account's asks and notices whose thread is gone.
func (s *SQLite) DeleteOrphanOwnerAsks(ctx context.Context, accountID string) (int64, error) {
	return s.q.DeleteOrphanOwnerAsks(ctx, accountID)
}

// ownerAsks maps a list of rows, or passes its error on.
func ownerAsks(rs []sqlitedb.OwnerAsk, err error) ([]OwnerAsk, error) {
	if err != nil {
		return nil, err
	}
	out := make([]OwnerAsk, 0, len(rs))
	for _, r := range rs {
		out = append(out, ownerAskFromRow(r))
	}
	return out, nil
}
