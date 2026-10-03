// Package auditstore joins the audit package to the store. The audit package describes the slice
// of the store it needs in its own terms, so it does not import the store package; this adapter is
// the join, shared by the offline `audit` commands and serve's sweep.
package auditstore

import (
	"context"
	"errors"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/audit"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Backing is what the adapter reads: the audit trail, and whether an account is still here.
type Backing interface {
	store.AuditStore
	GetAccountByID(ctx context.Context, id string) (store.Account, error)
}

// Adapter is a store seen as audit.Store and audit.DepartedStore.
type Adapter struct{ St Backing }

func rowsOf(rows []store.AuditRow) []audit.Row {
	out := make([]audit.Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.Row{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	return out
}

func (a Adapter) ListAuditEvents(ctx context.Context, actorFilter string) ([]audit.Row, error) {
	rows, err := a.St.ListAuditEvents(ctx, actorFilter)
	if err != nil {
		return nil, err
	}
	return rowsOf(rows), nil
}

func (a Adapter) AuditAnchor(ctx context.Context) (audit.Anchor, error) {
	row, err := a.St.AuditAnchor(ctx)
	if err != nil {
		return audit.Anchor{}, err
	}
	return audit.Anchor{
		ArchivedThroughSeq: row.ArchivedThroughSeq, TerminalHash: row.TerminalHash,
		ArchivePath: row.ArchivePath, UpdatedAt: row.UpdatedAt,
	}, nil
}

func (a Adapter) SetAuditAnchor(ctx context.Context, an audit.Anchor) error {
	return a.St.SetAuditAnchor(ctx, store.AuditAnchorRow{
		ArchivedThroughSeq: an.ArchivedThroughSeq, TerminalHash: an.TerminalHash,
		ArchivePath: an.ArchivePath, UpdatedAt: an.UpdatedAt,
	})
}

func (a Adapter) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return a.St.DeleteAuditEventsThrough(ctx, seq)
}

func (a Adapter) ListDueLeaves(ctx context.Context, before int64, limit int) ([]audit.Row, error) {
	rows, err := a.St.ListDueLeaves(ctx, before, limit)
	if err != nil {
		return nil, err
	}
	return rowsOf(rows), nil
}

func (a Adapter) ArchiveRows(ctx context.Context, rows []audit.Row) (int64, error) {
	named := make([]store.AuditArchiveRow, 0, len(rows))
	for _, r := range rows {
		named = append(named, store.AuditArchiveRow{Seq: r.Seq, Hash: r.Hash})
	}
	return a.St.ArchiveAuditRows(ctx, named)
}

func (a Adapter) AccountExists(ctx context.Context, accountID string) (bool, error) {
	_, err := a.St.GetAccountByID(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
