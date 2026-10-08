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
	// GetAccountByID returns the account, or store.ErrNotFound; AccountExists is its only use here.
	GetAccountByID(ctx context.Context, id string) (store.Account, error)
}

// Adapter is a store seen as audit.Store and audit.DepartedStore. It converts between the store's
// AuditRow and the audit package's Row and Anchor, and passes every error through unchanged. It
// holds no state and decides nothing.
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

// ListAuditEvents returns the whole trail ascending by seq, or one actor's rows when actorFilter is
// not empty (the store's ListAuditEvents), as audit.Rows.
func (a Adapter) ListAuditEvents(ctx context.Context, actorFilter string) ([]audit.Row, error) {
	rows, err := a.St.ListAuditEvents(ctx, actorFilter)
	if err != nil {
		return nil, err
	}
	return rowsOf(rows), nil
}

// AuditAnchor returns the archive anchor; the zero Anchor when the store has never archived.
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

// SetAuditAnchor records the anchor. The store refuses an anchor that moves backward, and that
// refusal is returned.
func (a Adapter) SetAuditAnchor(ctx context.Context, an audit.Anchor) error {
	return a.St.SetAuditAnchor(ctx, store.AuditAnchorRow{
		ArchivedThroughSeq: an.ArchivedThroughSeq, TerminalHash: an.TerminalHash,
		ArchivePath: an.ArchivePath, UpdatedAt: an.UpdatedAt,
	})
}

// DeleteAuditEventsThrough deletes the head rows through seq and returns how many went. The store's
// prune trigger refuses it unless the anchor already covers them.
func (a Adapter) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return a.St.DeleteAuditEventsThrough(ctx, seq)
}

// ListDueLeaves returns up to limit account_leave rows whose erase went through at or before the
// time `before`, oldest first: the identities whose trail is due to be archived.
func (a Adapter) ListDueLeaves(ctx context.Context, before int64, limit int) ([]audit.Row, error) {
	rows, err := a.St.ListDueLeaves(ctx, before, limit)
	if err != nil {
		return nil, err
	}
	return rowsOf(rows), nil
}

// ArchiveRows removes exactly the given rows, each named by seq and hash, in one transaction (the
// store's ArchiveAuditRows), and returns how many went. Only Seq and Hash of each row are sent.
func (a Adapter) ArchiveRows(ctx context.Context, rows []audit.Row) (int64, error) {
	named := make([]store.AuditArchiveRow, 0, len(rows))
	for _, r := range rows {
		named = append(named, store.AuditArchiveRow{Seq: r.Seq, Hash: r.Hash})
	}
	return a.St.ArchiveAuditRows(ctx, named)
}

// AccountExists reports whether the account is still on this node: false when the store answers
// ErrNotFound, and any other error is returned.
func (a Adapter) AccountExists(ctx context.Context, accountID string) (bool, error) {
	_, err := a.St.GetAccountByID(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
