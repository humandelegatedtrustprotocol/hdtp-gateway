package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) AuditAnchor(ctx context.Context) (AuditAnchorRow, error) {
	row, err := s.q.GetAuditAnchor(ctx)
	if errors.Is(err, sql.ErrNoRows) {
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

// SetAuditAnchor refuses to move the anchor BACKWARD. The prune trigger's whole
// strength is the anchor, so an anchor that can be rewritten freely is a guard
// that can be talked out of its job: lowering it turns a healthy chain into a
// reported break, and only ever raising it means a forged jump has to get past
// the archive step that verifies what it claims to have written.
func (s *SQLite) SetAuditAnchor(ctx context.Context, a AuditAnchorRow) error {
	if cur, err := s.AuditAnchor(ctx); err == nil && a.ArchivedThroughSeq < cur.ArchivedThroughSeq {
		return fmt.Errorf("store: the audit anchor cannot move backward (have %d, got %d)",
			cur.ArchivedThroughSeq, a.ArchivedThroughSeq)
	}
	return s.setAuditAnchor(ctx, a)
}

func (s *SQLite) setAuditAnchor(ctx context.Context, a AuditAnchorRow) error {
	return s.q.SetAuditAnchor(ctx, sqlitedb.SetAuditAnchorParams{
		ArchivedThroughSeq: a.ArchivedThroughSeq, TerminalHash: a.TerminalHash,
		ArchivePath: a.ArchivePath, UpdatedAt: a.UpdatedAt,
	})
}

func (s *SQLite) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return s.q.DeleteAuditEventsThrough(ctx, seq)
}

func (s *SQLite) ListDueLeaves(ctx context.Context, before int64, limit int) ([]AuditRow, error) {
	rs, err := s.q.ListDueLeaves(ctx, sqlitedb.ListDueLeavesParams{Ts: before, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, row := range rs {
		out = append(out, auditFromRow(row))
	}
	return out, nil
}

func (s *SQLite) ArchiveAuditRows(ctx context.Context, rows []AuditArchiveRow) (int64, error) {
	var n int64
	err := s.Atomically(ctx, func(tx Store) error {
		q := tx.(*SQLite).q
		if err := q.ClearAuditArchiveRows(ctx); err != nil {
			return err
		}
		for _, a := range rows {
			if err := q.InsertAuditArchiveRow(ctx, sqlitedb.InsertAuditArchiveRowParams{Seq: a.Seq, Hash: a.Hash}); err != nil {
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
