package messaging

// Bus is the node's event fan-out (SPEC §7.8): messages, contact requests, pending
// agent-answered calls and the rest wake the portal's SSE streams and the owner MCP's
// `wait_for_updates`, each of which re-reads the store. An event is a hint, never the ledger.
//
// Every event is also a row of the store's change log, so that every node process sharing the
// store hears it: Publish appends the row and delivers the event to this process's subscribers
// at once; Run polls the log (and, on Postgres, wakes on its notification) and delivers what
// other processes appended. Publishing never blocks on a subscriber: a full one drops the event
// and re-syncs from the store at its next read.

import (
	"context"
	"sync"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

type EventKind string

const (
	EventMessage EventKind = "message"
	EventRequest EventKind = "request"
	EventPending EventKind = "pending"
	// EventDelivery fires when an outbound message's delivery status changes —
	// delivered, or finally given up on. Without it a message
	// that failed and then succeeded on retry kept saying "not delivered yet"
	// until the owner reopened the conversation by hand.
	EventDelivery EventKind = "delivery"
	// EventCall: a contact made a substantive tool call (a booking, a media
	// send) — the change feed wakes so the agent can look. Ref names the tool.
	EventCall EventKind = "call"
	// EventAttention: a condition only the owner can clear arose — an
	// integration's token died and needs re-authorizing.
	EventAttention EventKind = "attention"
	// EventAnswered: the owner's agent answered an agent-answered request (Ref names it); the
	// call holding it, in whichever process, reads the answer from the store (SPEC §6.8).
	EventAnswered EventKind = "answered"
	// EventRelayed: the held call handed that answer to its caller (Ref names the request); the
	// process that took the answer reports it relayed.
	EventRelayed EventKind = "relayed"
)

// FeedCalls are the tools whose call means "a contact ACTED": the node publishes an EventCall
// for each one that succeeds, and the owner MCP's feed reports them. Messages are not here —
// threads carry those — and neither is `sealed_call`: its row fires on any opened envelope,
// refusals included, and the inner tool is what is published.
var FeedCalls = map[string]bool{
	"book_slot": true, "cancel_booking": true, "check_availability": true,
	"send_media": true, "get_status": true,
}

type Event struct {
	// ID is the change log's id for this event: the cursor `wait_for_updates` answers with.
	ID         int64     `json:"id,omitempty"`
	Kind       EventKind `json:"kind"`
	AccountID  string    `json:"account_id"`
	ThreadID   string    `json:"thread_id,omitempty"`
	ContactFpr string    `json:"contact_fpr,omitempty"`
	// Status is the new delivery status on an EventDelivery.
	Status string `json:"status,omitempty"`
	// Ref names what the event is about beyond the thread and the contact: the tool of an
	// EventCall, the request of an EventPending, EventAnswered or EventRelayed.
	Ref string `json:"ref,omitempty"`
}

// ChangeLog is the slice of the store the bus writes and reads.
type ChangeLog interface {
	AppendChange(ctx context.Context, c store.Change) (int64, error)
	ChangesAfter(ctx context.Context, after int64, limit int) ([]store.Change, error)
	ChangeBounds(ctx context.Context) (oldest, newest int64, err error)
	WatchChanges(ctx context.Context, wake func()) error
}

// PollInterval is how often Run reads the change log for what other processes wrote: the most a
// waiter in one process waits to hear of a change another process made, where no notification
// arrives sooner (SQLite has none).
const PollInterval = 250 * time.Millisecond

// pollPage is how many changes one read of the log takes; a full page is read again at once.
const pollPage = 500

type subscriber struct {
	accountID string
	ch        chan Event
}

type Bus struct {
	log ChangeLog
	now func() time.Time
	// OnError hears a change the log would not take or give; nil drops it. The event is still
	// delivered in this process; the others learn of what changed at their next read of the store.
	OnError func(error)

	mu   sync.Mutex
	subs map[*subscriber]struct{}
	// mine holds the ids this process appended and has already delivered, so Run passes over
	// them. One Run reads before Publish records its id is delivered twice, which a subscriber
	// takes as one more "look". Kept only while Run reads the log, and pruned below the newest
	// id it has read, so nothing is held for longer than a read.
	mine    map[int64]struct{}
	running bool
}

// NewBus is a bus over the store's change log.
func NewBus(log ChangeLog) *Bus {
	return &Bus{log: log, now: time.Now, subs: map[*subscriber]struct{}{}, mine: map[int64]struct{}{}}
}

// Subscribe delivers events for one account ("" for every account); cancel MUST be called when
// done.
func (b *Bus) Subscribe(accountID string) (<-chan Event, func()) {
	s := &subscriber{accountID: accountID, ch: make(chan Event, 32)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s.ch, func() {
		b.mu.Lock()
		delete(b.subs, s)
		b.mu.Unlock()
		close(s.ch)
	}
}

// Publish appends e to the change log and delivers it to this process's subscribers.
func (b *Bus) Publish(e Event) {
	id, err := b.log.AppendChange(context.Background(), store.Change{
		AccountID: e.AccountID, Kind: string(e.Kind), ThreadID: e.ThreadID,
		ContactFpr: e.ContactFpr, Ref: changeRef(e), At: b.now().Unix(),
	})
	if err != nil {
		b.fail(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		e.ID = id
		if b.running {
			b.mine[id] = struct{}{}
		}
	}
	b.deliverLocked(e)
}

func (b *Bus) fail(err error) {
	if b.OnError != nil {
		b.OnError(err)
	}
}

// deliverLocked fans e out without blocking. Caller holds b.mu.
func (b *Bus) deliverLocked(e Event) {
	for s := range b.subs {
		if s.accountID != "" && s.accountID != e.AccountID {
			continue
		}
		select {
		case s.ch <- e:
		default:
		}
	}
}

// changeRef is what an event carries in the log's ref column: a delivery's status, or the Ref.
func changeRef(e Event) string {
	if e.Kind == EventDelivery {
		return e.Status
	}
	return e.Ref
}

// EventOf is the event a change-log row records.
func EventOf(c store.Change) Event {
	e := Event{ID: c.ID, Kind: EventKind(c.Kind), AccountID: c.AccountID, ThreadID: c.ThreadID, ContactFpr: c.ContactFpr}
	if e.Kind == EventDelivery {
		e.Status = c.Ref
	} else {
		e.Ref = c.Ref
	}
	return e
}

// Run delivers what other processes append to the change log, from the newest id when it
// starts until ctx ends. It is the one reader of the log in a process: serve runs it in its
// joined background group.
func (b *Bus) Run(ctx context.Context) {
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.running = false
		clear(b.mine)
		b.mu.Unlock()
	}()
	_, last, err := b.log.ChangeBounds(ctx)
	if err != nil && ctx.Err() == nil {
		b.fail(err)
	}
	wake := make(chan struct{}, 1)
	var watching sync.WaitGroup
	watching.Go(func() {
		if err := b.log.WatchChanges(ctx, func() {
			select {
			case wake <- struct{}{}:
			default:
			}
		}); err != nil {
			b.fail(err)
		}
	})
	defer watching.Wait()
	tick := time.NewTicker(PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-wake:
		}
		last = b.poll(ctx, last)
	}
}

// poll delivers every change after last and returns the newest id it read.
func (b *Bus) poll(ctx context.Context, last int64) int64 {
	for {
		rows, err := b.log.ChangesAfter(ctx, last, pollPage)
		if err != nil {
			if ctx.Err() == nil {
				b.fail(err)
			}
			return last
		}
		b.mu.Lock()
		for _, c := range rows {
			last = c.ID
			if _, ok := b.mine[c.ID]; ok {
				continue
			}
			b.deliverLocked(EventOf(c))
		}
		for id := range b.mine {
			if id <= last {
				delete(b.mine, id)
			}
		}
		b.mu.Unlock()
		if len(rows) < pollPage {
			return last
		}
	}
}
