package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) AuditAnchor(ctx context.Context) (AuditAnchorRow, error) {
	row, err := p.q.GetAuditAnchor(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditAnchorRow{}, nil // never archived: the chain starts at genesis
	}
	if err != nil {
		return AuditAnchorRow{}, err
	}
	return AuditAnchorRow{
		ArchivedThroughSeq: row.ArchivedThroughSeq, TerminalHash: row.TerminalHash,
		ArchivePath: row.ArchivePath, UpdatedAt: row.UpdatedAt,
	}, nil
}

// SetAuditAnchor refuses to move the anchor BACKWARD — see the SQLite engine's
// note; the guard is the anchor, so the anchor needs one of its own.
func (p *Postgres) SetAuditAnchor(ctx context.Context, a AuditAnchorRow) error {
	if cur, err := p.AuditAnchor(ctx); err == nil && a.ArchivedThroughSeq < cur.ArchivedThroughSeq {
		return fmt.Errorf("store: the audit anchor cannot move backward (have %d, got %d)",
			cur.ArchivedThroughSeq, a.ArchivedThroughSeq)
	}
	return p.setAuditAnchor(ctx, a)
}

func (p *Postgres) setAuditAnchor(ctx context.Context, a AuditAnchorRow) error {
	return p.q.SetAuditAnchor(ctx, pgdb.SetAuditAnchorParams{
		ArchivedThroughSeq: a.ArchivedThroughSeq, TerminalHash: a.TerminalHash,
		ArchivePath: a.ArchivePath, UpdatedAt: a.UpdatedAt,
	})
}

func (p *Postgres) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return p.q.DeleteAuditEventsThrough(ctx, seq)
}
