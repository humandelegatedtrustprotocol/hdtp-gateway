package presence

import (
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/internalui/ownermcp"
)

// AC (P12-11, tightened by P13-02): the agent-answered service must know about
// owner presence from the moment it EXISTS, not from the moment the owner-MCP
// handler is built.
//
// SPEC §6.8 point 4: the fallback chain runs when the wait budget expires "or no
// agent is connected", and a nil Connected reads as "assume connected".
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
		t.Fatal("reported an owner agent connected when no owner request has arrived")
	}
	// The returned tracker is the one the agent consults — not a copy.
	presence.Seen()
	if !agent.Connected("any-account") {
		t.Fatal("a request seen by the returned tracker did not reach the agent")
	}
}

// An agent is present while its last owner-MCP request is younger than Window, and not after.
func TestOwnerPresenceIsARecentRequest(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	p := &Tracker{Now: func() time.Time { return now }}
	if p.Any() {
		t.Fatal("an empty tracker reported a live agent")
	}
	p.Seen()
	now = now.Add(Window - time.Second)
	if !p.Any() {
		t.Fatal("an agent seen within the window was not counted")
	}
	now = now.Add(time.Second)
	if p.Any() {
		t.Fatal("an agent silent for the whole window still counted as attached")
	}
}

// An agent waiting in a loop is never counted absent between two of its calls: the window is
// longer than the longest `wait_for_updates` may hold one.
func TestPresenceOutlastsTheLongestWait(t *testing.T) {
	if Window <= ownermcp.WaitMaxSec*time.Second {
		t.Fatalf("presence lasts %s after a request and wait_for_updates may hold one for %ds: an agent in a wait loop drops out", Window, ownermcp.WaitMaxSec)
	}
}
