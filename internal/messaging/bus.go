package messaging

// Bus is the internal event fan-out (SPEC §7.6): messages, contact requests, and
// pending agent-answered calls flow to the portal's SSE streams, the owner MCP's
// resource subscriptions, and the audit trail. Publishing never blocks: a slow
// subscriber drops events rather than stalling dispatch.

import "sync"

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
	// send) — the change feed wakes so the agent can look.
	EventCall EventKind = "call"
	// EventAttention: a condition only the owner can clear arose — an
	// integration's token died and needs re-authorizing.
	EventAttention EventKind = "attention"
)

type Event struct {
	Kind       EventKind `json:"kind"`
	AccountID  string    `json:"account_id"`
	ThreadID   string    `json:"thread_id,omitempty"`
	ContactFpr string    `json:"contact_fpr,omitempty"`
	// Status is the new delivery status on an EventDelivery.
	Status string `json:"status,omitempty"`
}

type subscriber struct {
	accountID string
	ch        chan Event
}

type Bus struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

func NewBus() *Bus { return &Bus{subs: map[*subscriber]struct{}{}} }

// Subscribe delivers events for one account; cancel MUST be called when done.
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

// Publish fans out without blocking; full subscribers miss the event (they
// re-sync from the store on next page load — SSE is a hint, not the ledger).
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
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
