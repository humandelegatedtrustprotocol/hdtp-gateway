package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// DeleteMessagesBefore deletes the account's messages created before cutoff and returns how many
// went. It deletes local copies only.
func (s *SQLite) DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error) {
	return s.q.DeleteMessagesBefore(ctx, sqlitedb.DeleteMessagesBeforeParams{AccountID: accountID, CreatedAt: cutoff})
}

// DeleteEmptyThreads deletes the account's threads that hold no message and returns how many went.
func (s *SQLite) DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error) {
	return s.q.DeleteEmptyThreads(ctx, accountID)
}

// DeleteExpiredIdempotency is two statements because each is answered from `idempotency_expiry`
// and one with an OR between them is not.
func (s *SQLite) DeleteExpiredIdempotency(ctx context.Context, now int64) (int64, error) {
	dated, err := s.q.DeleteExpiredIdempotency(ctx, sql.NullInt64{Int64: now, Valid: true})
	if err != nil {
		return 0, err
	}
	undated, err := s.q.DeleteUndatedIdempotencyBefore(ctx, now-int64(UndatedIdempotencyWindow.Seconds()))
	return dated + undated, err
}

// DeleteExpiredSessions deletes the sessions whose expiry is at or before now and returns how many
// went.
func (s *SQLite) DeleteExpiredSessions(ctx context.Context, now int64) (int64, error) {
	return s.q.DeleteExpiredSessions(ctx, now)
}

// ListMediaBodies returns the bodies of the account's media messages, oldest first, and no other
// message's.
func (s *SQLite) ListMediaBodies(ctx context.Context, accountID string) ([]string, error) {
	return s.q.ListMediaBodies(ctx, accountID)
}

// ListBlobs returns the account's blob records, oldest first.
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

// DeleteBlob deletes the account's blob record for hash and returns how many rows went. It removes
// the record, not the file.
func (s *SQLite) DeleteBlob(ctx context.Context, accountID, hash string) (int64, error) {
	return s.q.DeleteBlob(ctx, sqlitedb.DeleteBlobParams{AccountID: accountID, Hash: hash})
}

// CountBlobRefs counts the blob rows for hash across every account.
func (s *SQLite) CountBlobRefs(ctx context.Context, hash string) (int64, error) {
	return s.q.CountBlobRefs(ctx, hash)
}
