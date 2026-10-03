package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/audit"
)

// AuditAppender is a store seen as audit.Sink: the chain's writer seals an audit.Event on the head
// AppendAuditEvent read, and the store inserts it in the same transaction.
type AuditAppender struct{ St AuditStore }

func (a AuditAppender) AppendAuditEvent(ctx context.Context, seal func(prevSeq int64, prevHash string) (audit.Event, error)) error {
	return a.St.AppendAuditEvent(ctx, func(prevSeq int64, prevHash string) (AuditRow, error) {
		e, err := seal(prevSeq, prevHash)
		if err != nil {
			return AuditRow{}, err
		}
		return AuditRow{Seq: e.Seq, TS: e.TS, AccountID: e.AccountID, ActorKind: e.ActorKind, ActorID: e.ActorID,
			Action: e.Action, Resource: e.Resource, Outcome: e.Outcome, RequestID: e.RequestID, Details: e.Details,
			PrevHash: e.PrevHash, Hash: e.Hash}, nil
	})
}

// appendAudit is AppendAuditEvent's body, inside the transaction that holds the chain's head.
func appendAudit(ctx context.Context, tx Store, seal func(prevSeq int64, prevHash string) (AuditRow, error)) error {
	seq, hash, err := tx.LastAuditEvent(ctx)
	if errors.Is(err, ErrNotFound) {
		seq, hash, err = 0, "", nil
	}
	if err != nil {
		return fmt.Errorf("store: audit head: %w", err)
	}
	r, err := seal(seq, hash)
	if err != nil {
		return err
	}
	return tx.InsertAuditEvent(ctx, r.Seq, r.TS, r.AccountID, r.ActorKind, r.ActorID, r.Action, r.Resource,
		r.Outcome, r.RequestID, r.Details, r.PrevHash, r.Hash)
}
