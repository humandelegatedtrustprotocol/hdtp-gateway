package store

import (
	"context"
	"database/sql"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error) {
	return p.q.DeleteMessagesBefore(ctx, pgdb.DeleteMessagesBeforeParams{AccountID: accountID, CreatedAt: cutoff})
}

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

func (p *Postgres) DeleteExpiredSessions(ctx context.Context, now int64) (int64, error) {
	return p.q.DeleteExpiredSessions(ctx, now)
}

func (p *Postgres) ListMediaBodies(ctx context.Context, accountID string) ([]string, error) {
	return p.q.ListMediaBodies(ctx, accountID)
}

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

func (p *Postgres) DeleteBlob(ctx context.Context, accountID, hash string) (int64, error) {
	return p.q.DeleteBlob(ctx, pgdb.DeleteBlobParams{AccountID: accountID, Hash: hash})
}

func (p *Postgres) CountBlobRefs(ctx context.Context, hash string) (int64, error) {
	return p.q.CountBlobRefs(ctx, hash)
}
