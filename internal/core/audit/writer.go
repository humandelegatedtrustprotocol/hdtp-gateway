package audit

// Writer serializes appends onto the persistent chain (SPEC §11.4–§11.5): one
// writer per node, single mutex, seq and prev_hash carried in memory after the
// first load so every insert extends the stored chain.

import (
	"context"
	"sync"
	"time"
)

// Sink is the slice of the store the writer needs.
type Sink interface {
	InsertAuditEvent(ctx context.Context, seq int64, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) error
	LastAuditEvent(ctx context.Context) (seq int64, hash string, err error)
}

type Writer struct {
	Sink Sink
	Now  func() time.Time

	mu       sync.Mutex
	loaded   bool
	lastSeq  int64
	lastHash string
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Append seals and persists one event, extending the chain.
func (w *Writer) Append(ctx context.Context, accountID, actorKind, actorID, action, resource, outcome, requestID, details string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.loaded {
		seq, hash, err := w.Sink.LastAuditEvent(ctx)
		if err == nil {
			w.lastSeq, w.lastHash = seq, hash
		} else {
			w.lastSeq, w.lastHash = 0, GenesisHash
		}
		w.loaded = true
	}
	if details == "" {
		details = "{}"
	}
	e := Event{
		Seq: w.lastSeq + 1, TS: w.now().Unix(), AccountID: accountID,
		ActorKind: actorKind, ActorID: actorID, Action: action,
		Resource: resource, Outcome: outcome, RequestID: requestID, Details: details,
	}
	sealed, err := Next(w.lastHash, e)
	if err != nil {
		return err
	}
	if err := w.Sink.InsertAuditEvent(ctx, sealed.Seq, sealed.TS, sealed.AccountID,
		sealed.ActorKind, sealed.ActorID, sealed.Action, sealed.Resource,
		sealed.Outcome, sealed.RequestID, sealed.Details, sealed.PrevHash, sealed.Hash); err != nil {
		return err
	}
	w.lastSeq, w.lastHash = sealed.Seq, sealed.Hash
	return nil
}
