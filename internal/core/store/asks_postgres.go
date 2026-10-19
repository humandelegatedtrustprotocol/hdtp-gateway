package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertOwnerAsk writes a; false, writing nothing, when a unique key already holds it.
func (s *Postgres) InsertOwnerAsk(ctx context.Context, a OwnerAsk) (bool, error) {
	n, err := s.q.InsertOwnerAsk(ctx, pgdb.InsertOwnerAskParams(ownerAskInsert(a)))
	return n == 1, err
}

// GetOwnerAsk returns one of the account's asks or notices, or ErrNotFound.
func (s *Postgres) GetOwnerAsk(ctx context.Context, accountID, id string) (OwnerAsk, error) {
	r, err := s.q.GetOwnerAsk(ctx, pgdb.GetOwnerAskParams{AccountID: accountID, ID: id})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(sqlitedb.OwnerAsk(r)), nil
}

// GetOwnerAskFor returns the ask or notice of that kind about that message, or ErrNotFound.
func (s *Postgres) GetOwnerAskFor(ctx context.Context, accountID, kind, threadID, forMsgID string) (OwnerAsk, error) {
	r, err := s.q.GetOwnerAskFor(ctx, pgdb.GetOwnerAskForParams{AccountID: accountID, Kind: kind, ThreadID: threadID, ForMsgID: forMsgID})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(sqlitedb.OwnerAsk(r)), nil
}

// GetOpenOwnerAsk returns the thread's open ask, or ErrNotFound.
func (s *Postgres) GetOpenOwnerAsk(ctx context.Context, accountID, threadID string) (OwnerAsk, error) {
	r, err := s.q.GetOpenOwnerAsk(ctx, pgdb.GetOpenOwnerAskParams{AccountID: accountID, ThreadID: threadID})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(sqlitedb.OwnerAsk(r)), nil
}

// GetContactOpenOwnerAsk returns the newest open ask of any thread with the contact, or ErrNotFound.
func (s *Postgres) GetContactOpenOwnerAsk(ctx context.Context, accountID, contactFpr string) (OwnerAsk, error) {
	r, err := s.q.GetContactOpenOwnerAsk(ctx, pgdb.GetContactOpenOwnerAskParams{AccountID: accountID, ContactFpr: contactFpr})
	if err != nil {
		return OwnerAsk{}, err
	}
	return ownerAskFromRow(sqlitedb.OwnerAsk(r)), nil
}

// ListOwnerAsks returns up to limit of the account's asks and notices, newest first.
func (s *Postgres) ListOwnerAsks(ctx context.Context, accountID string, limit int) ([]OwnerAsk, error) {
	return pgOwnerAsks(s.q.ListOwnerAsks(ctx, pgdb.ListOwnerAsksParams{AccountID: accountID, Limit: pgLimit(limit)}))
}

// ListOpenOwnerAsks returns up to limit of the account's open asks, newest first.
func (s *Postgres) ListOpenOwnerAsks(ctx context.Context, accountID string, limit int) ([]OwnerAsk, error) {
	return pgOwnerAsks(s.q.ListOpenOwnerAsks(ctx, pgdb.ListOpenOwnerAsksParams{AccountID: accountID, Limit: pgLimit(limit)}))
}

// ListThreadOwnerAsks returns up to limit asks and notices of one thread, newest first.
func (s *Postgres) ListThreadOwnerAsks(ctx context.Context, accountID, threadID string, limit int) ([]OwnerAsk, error) {
	return pgOwnerAsks(s.q.ListThreadOwnerAsks(ctx, pgdb.ListThreadOwnerAsksParams{AccountID: accountID, ThreadID: threadID, Limit: pgLimit(limit)}))
}

// ListContactOwnerAsks returns up to limit asks and notices of the threads with one contact, newest
// first.
func (s *Postgres) ListContactOwnerAsks(ctx context.Context, accountID, contactFpr string, limit int) ([]OwnerAsk, error) {
	return pgOwnerAsks(s.q.ListContactOwnerAsks(ctx, pgdb.ListContactOwnerAsksParams{AccountID: accountID, ContactFpr: contactFpr, Limit: pgLimit(limit)}))
}

// CountOpenOwnerAsks counts the account's open asks that have not expired by now.
func (s *Postgres) CountOpenOwnerAsks(ctx context.Context, accountID string, now int64) (int64, error) {
	return s.q.CountOpenOwnerAsks(ctx, pgdb.CountOpenOwnerAsksParams{AccountID: accountID, ExpiresAt: now})
}

// CloseOwnerAsk moves an open, unexpired ask to status with the answer line; false for any other.
func (s *Postgres) CloseOwnerAsk(ctx context.Context, accountID, id, status, answer string, now int64) (bool, error) {
	n, err := s.q.CloseOwnerAsk(ctx, pgdb.CloseOwnerAskParams{Status: status, AnswerText: answer, UpdatedAt: now, AccountID: accountID, ID: id, ExpiresAt: now})
	return n == 1, err
}

// ExpireOwnerAsk moves an open ask whose time has come to expired; false for any other.
func (s *Postgres) ExpireOwnerAsk(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ExpireOwnerAsk(ctx, pgdb.ExpireOwnerAskParams{UpdatedAt: now, AccountID: accountID, ID: id, ExpiresAt: now})
	return n == 1, err
}

// ListDueOwnerAsks returns up to limit open asks, of every account, whose time has come.
func (s *Postgres) ListDueOwnerAsks(ctx context.Context, now int64, limit int) ([]OwnerAsk, error) {
	return pgOwnerAsks(s.q.ListDueOwnerAsks(ctx, pgdb.ListDueOwnerAsksParams{ExpiresAt: now, Limit: pgLimit(limit)}))
}

// DeleteThreadOwnerAsks deletes one thread's asks and notices and returns how many went.
func (s *Postgres) DeleteThreadOwnerAsks(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.DeleteThreadOwnerAsks(ctx, pgdb.DeleteThreadOwnerAsksParams{AccountID: accountID, ThreadID: threadID})
}

// DeleteOrphanOwnerAsks deletes the account's asks and notices whose thread is gone.
func (s *Postgres) DeleteOrphanOwnerAsks(ctx context.Context, accountID string) (int64, error) {
	return s.q.DeleteOrphanOwnerAsks(ctx, accountID)
}

// pgOwnerAsks maps a list of rows, or passes its error on.
func pgOwnerAsks(rs []pgdb.OwnerAsk, err error) ([]OwnerAsk, error) {
	if err != nil {
		return nil, err
	}
	out := make([]OwnerAsk, 0, len(rs))
	for _, r := range rs {
		out = append(out, ownerAskFromRow(sqlitedb.OwnerAsk(r)))
	}
	return out, nil
}
