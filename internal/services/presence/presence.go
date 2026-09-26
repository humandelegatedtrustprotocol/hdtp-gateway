// Package presence answers whether the owner's agent is attached to the owner MCP right now,
// which decides how an agent-answered request waits (SPEC §6.8).
package presence

import (
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
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
// The owner MCP is account-agnostic — the token identity scopes each call, not
// the server — so this is deliberately a node-wide answer and the account id is
// ignored. Servers are registered as they are created and pruned once they hold
// no sessions, so a reconnecting agent does not accumulate entries.
type Tracker struct {
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries []*presenceEntry
}

type presenceEntry struct {
	srv *mcp.Server
	// added is when the server was registered. A server is created by getServer
	// BEFORE the SDK attaches its session, so pruning on "has no sessions" alone
	// would discard a live agent in the gap between the two — and that agent
	// would then never count. Give a new server a grace period to acquire one.
	added time.Time
	// saw records that this server HAS held a session. Once true, "no sessions"
	// means the agent left rather than has not arrived, and it can go at once.
	saw bool
}

// presenceGrace is how long a newly created server may hold no session before it
// is treated as abandoned.
const presenceGrace = time.Minute

func (p *Tracker) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Tracker) Add(s *mcp.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, &presenceEntry{srv: s, added: p.now()})
}

func (p *Tracker) Any() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	live := p.entries[:0]
	found := false
	for _, e := range p.entries {
		has := false
		for range e.srv.Sessions() {
			has = true
			break
		}
		switch {
		case has:
			e.saw = true
			live = append(live, e)
			found = true
		case !e.saw && now.Sub(e.added) < presenceGrace:
			live = append(live, e) // still arriving
		}
	}
	p.entries = live
	return found
}
