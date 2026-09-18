package store

import (
	"context"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error) {
	return s.q.DeleteMessagesBefore(ctx, sqlitedb.DeleteMessagesBeforeParams{AccountID: accountID, CreatedAt: cutoff})
}

func (s *SQLite) DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error) {
	// The account is named twice because the statement compares it twice: the threads
	// to consider, and the messages that keep one alive.
	return s.q.DeleteEmptyThreads(ctx, sqlitedb.DeleteEmptyThreadsParams{AccountID: accountID, AccountID_2: accountID})
}

func (s *SQLite) ListBlobs(ctx context.Context, accountID string) ([]Blob, error) {
	rows, err := s.q.ListBlobs(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Blob, 0, len(rows))
	for _, r := range rows {
		out = append(out, Blob{
			AccountID: r.AccountID, Hash: r.Hash, Size: r.Size,
			Mime: r.Mime, Filename: r.Filename, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (s *SQLite) DeleteBlob(ctx context.Context, accountID, hash string) (int64, error) {
	return s.q.DeleteBlob(ctx, sqlitedb.DeleteBlobParams{AccountID: accountID, Hash: hash})
}

func (s *SQLite) CountBlobRefs(ctx context.Context, hash string) (int64, error) {
	return s.q.CountBlobRefs(ctx, hash)
}
