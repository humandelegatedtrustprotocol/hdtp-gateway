package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
)

// DeleteMessagesBefore deletes the account's messages created before cutoff and returns how many
// went. It deletes local copies only.
func (p *Postgres) DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error) {
	return p.q.DeleteMessagesBefore(ctx, pgdb.DeleteMessagesBeforeParams{AccountID: accountID, CreatedAt: cutoff})
}

// DeleteEmptyThreads deletes the account's threads that hold no message and returns how many went.
func (p *Postgres) DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error) {
	return p.q.DeleteEmptyThreads(ctx, accountID)
}

// DeleteExpiredIdempotency is two statements; see the sqlite side for why.
func (p *Postgres) DeleteExpiredIdempotency(ctx context.Context, now int64) (int64, error) {
	dated, err := p.q.DeleteExpiredIdempotency(ctx, sql.NullInt64{Int64: now, Valid: true})
	if err != nil {
		return 0, err
	}
	undated, err := p.q.DeleteUndatedIdempotencyBefore(ctx, now-int64(UndatedIdempotencyWindow.Seconds()))
	return dated + undated, err
}

// DeleteExpiredSessions deletes the sessions whose expiry is at or before now and returns how many
// went.
func (p *Postgres) DeleteExpiredSessions(ctx context.Context, now int64) (int64, error) {
	return p.q.DeleteExpiredSessions(ctx, now)
}

// ListMediaBodies returns the bodies of the account's media messages, oldest first, and no other
// message's.
func (p *Postgres) ListMediaBodies(ctx context.Context, accountID string) ([]string, error) {
	return p.q.ListMediaBodies(ctx, accountID)
}

// ListBlobs returns the account's blob records, oldest first.
func (p *Postgres) ListBlobs(ctx context.Context, accountID string) ([]Blob, error) {
	rows, err := p.q.ListBlobs(ctx, accountID)
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
func (p *Postgres) DeleteBlob(ctx context.Context, accountID, hash string) (int64, error) {
	return p.q.DeleteBlob(ctx, pgdb.DeleteBlobParams{AccountID: accountID, Hash: hash})
}

// CountBlobRefs counts the blob rows for hash across every account.
func (p *Postgres) CountBlobRefs(ctx context.Context, hash string) (int64, error) {
	return p.q.CountBlobRefs(ctx, hash)
}
