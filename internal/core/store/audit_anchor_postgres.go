package store

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
	"github.com/pact-cloud/pact-gateway/internal/core/store/sqlitedb"
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

func (p *Postgres) ListDueLeaves(ctx context.Context, before int64, limit int) ([]AuditRow, error) {
	// Postgres types LIMIT as int32: a limit that cannot fit is clamped, not wrapped (gosec G115).
	var lim int32 = math.MaxInt32
	if limit >= 0 && limit <= math.MaxInt32 {
		lim = int32(limit)
	}
	rs, err := p.q.ListDueLeaves(ctx, pgdb.ListDueLeavesParams{Ts: before, Limit: lim})
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, row := range rs {
		out = append(out, auditFromRow(sqlitedb.AuditEvent(row)))
	}
	return out, nil
}

func (p *Postgres) ArchiveAuditRows(ctx context.Context, rows []AuditArchiveRow) (int64, error) {
	var n int64
	err := p.Atomically(ctx, func(tx Store) error {
		q := tx.(*Postgres).q
		if err := q.ClearAuditArchiveRows(ctx); err != nil {
			return err
		}
		for _, a := range rows {
			if err := q.InsertAuditArchiveRow(ctx, pgdb.InsertAuditArchiveRowParams{Seq: a.Seq, Hash: a.Hash}); err != nil {
				return err
			}
		}
		for _, a := range rows {
			d, err := q.DeleteArchivedAuditEvent(ctx, a.Seq)
			if err != nil {
				return err
			}
			n += d
		}
		if n != int64(len(rows)) {
			return fmt.Errorf("store: an archive named %d audit row(s) and %d of them are in the chain as named", len(rows), n)
		}
		return q.ClearAuditArchiveRows(ctx)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
