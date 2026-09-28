// Package presence answers whether the owner's agent is attached to the owner MCP right now,
// which decides how an agent-answered request waits (SPEC §6.8).
package presence

import (
	"context"
	"sync"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/integrations"
)

// NewAgentAnswered builds the agent-answered service together with the tracker
// that answers its Connected question (SPEC §6.8).
//
// They are created together on purpose. The tracker used to be made inside
// ownerMCPHandler, which `serve` does not build until AFTER nd.Start has opened
// the PUBLIC listener and the stored integrations have been reconnected — and
// reconnecting is exactly what republishes agent-answered exposures. So for the
// whole of boot, Connected was nil again and a contact calling an agent-answered
// capability was held for the full wait budget: the defect P12-11 fixed,
// reachable through the startup window it left behind. Pairing them here means
// there is no moment when one exists without the other.
func NewAgentAnswered(st store.Store, audit func(action, resource, outcome string)) (*integrations.AgentAnswered, *Tracker) {
	presence := &Tracker{Store: st}
	return &integrations.AgentAnswered{
		Store: st, Audit: audit,
		Connected: func(string) bool { return presence.Any() },
	}, presence
}

// PresenceStore is where the owner agent's last request is kept, so that every node process
// sharing the store answers the same.
type PresenceStore interface {
	TouchOwnerPresence(ctx context.Context, at int64) error
	OwnerPresenceSeenAt(ctx context.Context) (int64, error)
}

// Tracker answers "is the owner's agent attached right now?" (SPEC §6.8).
//
// The owner MCP is stateless (SPEC §8.5): there is no session to be attached by, only requests.
// An agent that is attached is one that keeps asking — `wait_for_updates` in a loop holds each
// call for at most its timeout — so the agent counts as present while its last request is less
// than Window old. The last request is kept in the store, so a request to one node process makes
// the agent present on every process sharing it. The owner MCP is account-agnostic — the token
// identity scopes each call, not the server — so this is deliberately a node-wide answer and the
// account id is ignored.
type Tracker struct {
	Store PresenceStore
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	mu        sync.Mutex
	lastWrite time.Time
}

// Window is how long after its last owner-MCP request the agent still counts as attached. It is
// longer than the longest a `wait_for_updates` may hold one call (ownermcp.WaitMaxSec) plus
// SeenEvery, held to both by a test, so an agent waiting in a loop never drops out between two of
// its calls. It compares one process's write with another's clock: processes on hosts whose
// clocks differ by more than the room left in it disagree.
const Window = time.Minute

// SeenEvery is how often one process records the agent's requests: at most one write per
// SeenEvery, however often the agent asks.
const SeenEvery = 5 * time.Second

func (p *Tracker) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Seen records an authenticated owner-MCP request. A write that fails is not retried until
// SeenEvery has passed: presence is a hint for how long a call is held, never an authorization.
func (p *Tracker) Seen() {
	now := p.now()
	p.mu.Lock()
	if !p.lastWrite.IsZero() && now.Sub(p.lastWrite) < SeenEvery {
		p.mu.Unlock()
		return
	}
	p.lastWrite = now
	p.mu.Unlock()
	_ = p.Store.TouchOwnerPresence(context.Background(), now.Unix())
}

// Any reports whether an owner-MCP request arrived, at any process on the store, within Window.
func (p *Tracker) Any() bool {
	at, err := p.Store.OwnerPresenceSeenAt(context.Background())
	if err != nil || at == 0 {
		return false
	}
	return p.now().Sub(time.Unix(at, 0)) < Window
}
