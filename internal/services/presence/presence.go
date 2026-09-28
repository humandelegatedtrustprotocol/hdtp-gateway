// Package presence answers whether the owner's agent is attached to the owner MCP right now,
// which decides how an agent-answered request waits (SPEC §6.8).
package presence

import (
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
	presence := &Tracker{}
	return &integrations.AgentAnswered{
		Store: st, Audit: audit,
		Connected: func(string) bool { return presence.Any() },
	}, presence
}

// Tracker answers "is the owner's agent attached right now?" (SPEC §6.8).
//
// The owner MCP is stateless (SPEC §8.5): there is no session to be attached by, only requests.
// An agent that is attached is one that keeps asking — `wait_for_updates` in a loop holds each
// call for at most its timeout — so the agent counts as present while its last request is less
// than Window old. The owner MCP is account-agnostic — the token identity scopes each call, not
// the server — so this is deliberately a node-wide answer and the account id is ignored.
type Tracker struct {
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	mu   sync.Mutex
	last time.Time
}

// Window is how long after its last owner-MCP request the agent still counts as attached. It is
// longer than the longest a `wait_for_updates` may hold one call (ownermcp.WaitMaxSec, held to
// this by a test), so an agent waiting in a loop never drops out between two of its calls.
const Window = time.Minute

func (p *Tracker) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Seen records an authenticated owner-MCP request.
func (p *Tracker) Seen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = p.now()
}

// Any reports whether an owner-MCP request arrived within Window.
func (p *Tracker) Any() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.last.IsZero() && p.now().Sub(p.last) < Window
}
