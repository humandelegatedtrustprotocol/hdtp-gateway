package public

import (
	"context"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// PACT §5.2's "an address that belongs to someone" has two copies on the node: the core's Decide
// computes it for a sealed guest (its address_claim, carried as EnvelopeFacts.AddressClaim), and
// contacts.Manager.AddressClaim asks the store for a guest proven by its client certificate, which
// Decide never sees. The same state goes through both here, and the two answers must agree — for
// an address pinned for another root, a former address inside the window, one past it, and one
// nobody held.
func TestTheTwoAddressClaimsAgree(t *testing.T) {
	e := newRecvEnv(t)
	ctx := context.Background()
	friend := newPeer(t, fixedNow)
	e.pin(t, friend, "active")
	m := &contacts.Manager{Store: e.st, Now: func() time.Time { return e.nowAt }}

	const recent, stale, fresh = "https://recent.example/mcp", "https://stale.example/mcp", "https://fresh.example/mcp"
	for _, f := range []store.FormerEndpoint{
		{AccountID: e.acct.ID, Root: "sha256:moved-lately", Endpoint: recent, At: fixedNow.Add(-pactidentity.ClaimWindow + time.Hour).Unix()},
		{AccountID: e.acct.ID, Root: "sha256:moved-long-ago", Endpoint: stale, At: fixedNow.Add(-pactidentity.ClaimWindow - time.Hour).Unix()},
	} {
		if err := e.st.InsertFormerEndpoint(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	claimed := 0
	for _, at := range []string{endpointA, recent, stale, fresh} {
		s := newPeer(t, fixedNow)
		s.leaf = s.leafFor(t, at, fixedNow.Add(-time.Hour))
		facts, err := e.open(t, e.sealFrom(t, s, "chain", "request_contact", map[string]any{"card": cardOf(s)}), TransportFacts{})
		if err != nil {
			t.Fatalf("%s: the sealed guest was refused: %v", at, err)
		}
		fromStore, err := m.AddressClaim(ctx, e.acct.ID, at, s.fpr())
		if err != nil {
			t.Fatal(err)
		}
		if facts.AddressClaim != fromStore {
			t.Errorf("%s: the core claims %q, the store %q", at, facts.AddressClaim, fromStore)
		}
		if fromStore != "" {
			claimed++
		}
	}
	// Two of the four are claimed; agreeing on nothing but empty answers would prove nothing.
	if claimed != 2 {
		t.Errorf("%d addresses claimed, want the pinned one and the recent former one", claimed)
	}
}
