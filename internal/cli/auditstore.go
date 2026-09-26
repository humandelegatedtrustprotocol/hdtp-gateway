package cli

// The audit package describes the slice of the store it needs in its own terms,
// so it does not import the store package. This adapter is the join.

import (
	"context"

	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

type auditStore struct{ st store.AuditStore }

func (a auditStore) ListAuditEvents(ctx context.Context, actorFilter string) ([]audit.Row, error) {
	rows, err := a.st.ListAuditEvents(ctx, actorFilter)
	if err != nil {
		return nil, err
	}
	out := make([]audit.Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.Row{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	return out, nil
}

func (a auditStore) AuditAnchor(ctx context.Context) (audit.Anchor, error) {
	row, err := a.st.AuditAnchor(ctx)
	if err != nil {
		return audit.Anchor{}, err
	}
	return audit.Anchor{
		ArchivedThroughSeq: row.ArchivedThroughSeq, TerminalHash: row.TerminalHash,
		ArchivePath: row.ArchivePath, UpdatedAt: row.UpdatedAt,
	}, nil
}

func (a auditStore) SetAuditAnchor(ctx context.Context, an audit.Anchor) error {
	return a.st.SetAuditAnchor(ctx, store.AuditAnchorRow{
		ArchivedThroughSeq: an.ArchivedThroughSeq, TerminalHash: an.TerminalHash,
		ArchivePath: an.ArchivePath, UpdatedAt: an.UpdatedAt,
	})
}

func (a auditStore) DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error) {
	return a.st.DeleteAuditEventsThrough(ctx, seq)
}
