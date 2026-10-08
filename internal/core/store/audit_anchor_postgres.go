package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// AuditAnchor reads the archive anchor row. A node that has never archived has none, and the zero
// AuditAnchorRow is returned with a nil error.
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

// DeleteAuditEventsThrough deletes the audit rows with seq at or below seq and returns how many
// went. The prune trigger refuses the delete unless the anchor already covers them, so
// SetAuditAnchor comes first.
func (p *Postgres) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return p.q.DeleteAuditEventsThrough(ctx, seq)
}

// ListDueLeaves returns up to limit account_leave audit rows whose erase went through (outcome ok or
// partial) at or before the time `before`, oldest first.
func (p *Postgres) ListDueLeaves(ctx context.Context, before int64, limit int) ([]AuditRow, error) {
	rs, err := p.q.ListDueLeaves(ctx, pgdb.ListDueLeavesParams{Ts: before, Limit: pgLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, row := range rs {
		out = append(out, auditFromRow(sqlitedb.AuditEvent(row)))
	}
	return out, nil
}

// ArchiveAuditRows removes exactly the named rows from the audit chain in one transaction, see
// AuditStore.ArchiveAuditRows. It empties audit_archive_rows, lists the named seqs with their
// hashes, deletes each, and rolls everything back unless the number deleted equals the number named.
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
