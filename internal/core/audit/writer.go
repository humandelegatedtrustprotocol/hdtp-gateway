package audit

// Writer appends onto the persistent chain (SPEC §11.4–§11.5). Each append reads the chain's
// head and writes the next row in one transaction that holds the head (Sink.AppendAuditEvent), so
// any number of writers — goroutines, and node processes sharing one store — extend one chain and
// never write two rows on one head. Nothing about the head is kept between appends.

import (
	"context"
	"sync"
	"time"
)

// Sink is the slice of the store the writer needs: the store's AppendAuditEvent, in the audit
// package's terms (auditstore.Adapter is the join).
type Sink interface {
	AppendAuditEvent(ctx context.Context, seal func(prevSeq int64, prevHash string) (Event, error)) error
}

// Writer seals events onto the chain and hands them to Sink to be inserted. It is the only
// production code that builds a chain row (through Next): the node's audit sink
// (internal/services/auditsink) holds one for every row `serve` writes, and `audit erase-archive`
// holds one for its own. Now defaults to time.Now. A Writer is safe for concurrent use, within one
// process and across processes that share a store.
type Writer struct {
	Sink Sink
	Now  func() time.Time

	// mu queues this process's appends, so they wait here rather than inside the store's lock.
	// It is a courtesy, not the guarantee: the transaction is.
	mu sync.Mutex
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Append seals one event onto the chain and persists it. Seq is the head's plus one, TS is Now in
// unix seconds, and an empty details is stored as "{}". On an empty chain the event follows
// GenesisHash. The Sink reads the head and inserts the row in one transaction, so Append never
// writes two rows on one head; an error from the Sink means no row was written.
func (w *Writer) Append(ctx context.Context, accountID, actorKind, actorID, action, resource, outcome, requestID, details string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if details == "" {
		details = "{}"
	}
	return w.Sink.AppendAuditEvent(ctx, func(prevSeq int64, prevHash string) (Event, error) {
		if prevSeq == 0 && prevHash == "" {
			prevHash = GenesisHash
		}
		return Next(prevHash, Event{
			Seq: prevSeq + 1, TS: w.now().Unix(), AccountID: accountID,
			ActorKind: actorKind, ActorID: actorID, Action: action,
			Resource: resource, Outcome: outcome, RequestID: requestID, Details: details,
		})
	})
}
