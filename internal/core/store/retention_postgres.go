package store

import (
	"context"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error) {
	return p.q.DeleteMessagesBefore(ctx, pgdb.DeleteMessagesBeforeParams{AccountID: accountID, CreatedAt: cutoff})
}

func (p *Postgres) DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error) {
	// The account is named twice because the statement compares it twice: the threads
	// to consider, and the messages that keep one alive.
	return p.q.DeleteEmptyThreads(ctx, pgdb.DeleteEmptyThreadsParams{AccountID: accountID, AccountID_2: accountID})
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
