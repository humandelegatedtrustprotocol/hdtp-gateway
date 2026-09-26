package presence

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AC (P12-11, tightened by P13-02): the agent-answered service must know about
// owner presence from the moment it EXISTS, not from the moment the owner-MCP
// handler is built.
//
// SPEC §6.8 point 4: the fallback chain runs when the wait budget expires "or no
// agent session is connected", and a nil Connected reads as "assume connected".
// P12-11 set it inside ownerMCPHandler — which `serve` does not build until
// after nd.Start has opened the PUBLIC listener and the stored integrations have
// been reconnected, and reconnecting is what republishes agent-answered
// exposures. For the whole of boot the field was nil again, so a contact calling
// an agent-answered capability was held for the full 30 s budget: the defect
// P12-11 fixed, through the startup window it left behind.
//
// Pairing the two in one constructor is what makes the window unreachable, so
// that is what this pins — not a line ordering somebody can quietly move.
func TestAgentAnsweredKnowsAboutPresenceFromConstruction(t *testing.T) {
	agent, presence := NewAgentAnswered(nil, nil)
	if agent == nil || presence == nil {
		t.Fatal("the constructor returned a nil half")
	}
	if agent.Connected == nil {
		t.Fatal("AgentAnswered was born with Connected nil, so during boot the node " +
			"assumes an owner agent is listening when none is")
	}
	if agent.Connected("any-account") {
		t.Fatal("reported an owner agent connected when no owner session exists")
	}
	// The returned tracker is the one the agent consults — not a copy.
	srv := mcp.NewServer(&mcp.Implementation{Name: "owner", Version: "1"}, nil)
	presence.Add(srv)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "a", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cs.Close(); ss.Wait() }()
	if !agent.Connected("any-account") {
		t.Fatal("a session on the returned tracker did not reach the agent")
	}
}

// Tracker prunes servers that no longer hold a session, so a reconnecting
// agent does not accumulate entries and a departed one stops counting.
func TestOwnerPresenceTracksLiveSessionsOnly(t *testing.T) {
	p := &Tracker{}
	if p.Any() {
		t.Fatal("an empty tracker reported a live agent")
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "owner", Version: "1"}, nil)
	p.Add(srv)
	if p.Any() {
		t.Fatal("a server with no sessions reported a live agent")
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "a", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Any() {
		t.Fatal("a connected owner session was not seen")
	}
	cs.Close()
	ss.Wait()
	if p.Any() {
		t.Fatal("a closed owner session still counted as a live agent")
	}
	if len(p.entries) != 0 {
		t.Fatalf("%d dead servers retained; the tracker grows per reconnect", len(p.entries))
	}
}
