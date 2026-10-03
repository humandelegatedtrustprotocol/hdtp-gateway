package presence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/ownermcp"
)

func migratedAt(t *testing.T, path string) *store.SQLite {
	t.Helper()
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

// AC (P12-11, tightened by P13-02): the agent-answered service must know about
// owner presence from the moment it EXISTS, not from the moment the owner-MCP
// handler is built.
//
// SPEC §6.8 point 4: the fallback chain runs when the wait budget expires "or no
// agent is attached", and a nil Connected reads as "assume connected".
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
	agent, presence := NewAgentAnswered(migratedAt(t, filepath.Join(t.TempDir(), "p.db")), nil)
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

// An agent is present while its last owner-MCP request is younger than Window, and not after;
// and a request to one node process makes it present on another sharing the store.
func TestOwnerPresenceIsARecentRequestOnAnyProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	here := &Tracker{Store: migratedAt(t, path), Now: clock}
	there := &Tracker{Store: migratedAt(t, path), Now: clock}
	if here.Any() || there.Any() {
		t.Fatal("an empty store reported a live agent")
	}
	here.Seen()
	now = now.Add(Window - time.Second)
	if !there.Any() {
		t.Fatal("an agent seen by one process within the window was not present on the other")
	}
	now = now.Add(time.Second)
	if there.Any() || here.Any() {
		t.Fatal("an agent silent for the whole window still counted as attached")
	}
}

// One process writes the agent's presence at most once per SeenEvery, however often it asks.
func TestPresenceIsWrittenAtMostOncePerInterval(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	st := migratedAt(t, filepath.Join(t.TempDir(), "p.db"))
	p := &Tracker{Store: st, Now: func() time.Time { return now }}
	p.Seen()
	first, _ := st.OwnerPresenceSeenAt(context.Background())
	now = now.Add(SeenEvery - time.Second)
	p.Seen()
	if again, _ := st.OwnerPresenceSeenAt(context.Background()); again != first {
		t.Fatal("a request within SeenEvery wrote presence again")
	}
	now = now.Add(time.Second)
	p.Seen()
	if later, _ := st.OwnerPresenceSeenAt(context.Background()); later != now.Unix() {
		t.Fatalf("a request after SeenEvery did not write presence: %d", later)
	}
}

// An agent waiting in a loop is never counted absent between two of its calls: the window is
// longer than the longest `wait_for_updates` may hold one, plus the interval a write may lag.
func TestPresenceOutlastsTheLongestWait(t *testing.T) {
	if Window <= ownermcp.WaitMaxSec*time.Second+SeenEvery {
		t.Fatalf("presence lasts %s after a request, a wait may hold one for %ds and a write may lag %s: an agent in a wait loop drops out", Window, ownermcp.WaitMaxSec, SeenEvery)
	}
}
