package node

// The transport path (PACT §2): a chain presented as the TLS client
// certificate earns exactly what the sealed path would grant the same chain —
// resolved through the pin checks of §14.3 and §5.3 before the per-caller
// server is composed, so what tools/list shows and what a call runs as agree
// with what an envelope carrying that chain would have been decided as.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
)

func TestPact20TransportChainResolvesThroughThePinChecks(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 2, 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 2, 365)
	// Plaintext calls reach Alina only when her policy allows them.
	if err := alina.n.SetSeal(ctx, alina.acct.ID, core.SealOptional); err != nil {
		t.Fatal(err)
	}
	alina.pin20(bharat)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Fingerprint: alina.rootFpr(), Seal: "optional", Protocol: 2, Root: alina.rootFpr(), Leaf: alina.leaf()}
	clientFor := func(kp *identity.Keypair) *outbound.Client {
		return bharat.n.wire20(bharat.acct.ID, &outbound.Client{Keypair: kp, Cert: tlsCertOf(kp)})
	}
	names := func(c *outbound.Client) map[string]bool {
		tools, err := c.ListTools(ctx, peerA)
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		out := map[string]bool{}
		for _, tool := range tools {
			out[tool.Name] = true
		}
		return out
	}

	// The current chain: a contact, in the listing and in a call.
	current := clientFor(bharat.kp())
	if got := names(current); !got["send_message"] {
		t.Fatalf("the current chain must be listed as a contact: %v", got)
	}

	// Bharat renews. Alina learns the new leaf on the transport path — a
	// renewal at the pinned endpoint replaces the pin as it passes (§14.3).
	clock.advance(time.Hour)
	ren := bharat.install(identity.PurposeRenew, bharat.endpoint(), 365, clock.now())
	if ren.OldKP == nil {
		t.Fatal("the renewal must hand back the superseded key")
	}
	renewed := clientFor(bharat.kp())
	if got := names(renewed); !got["send_message"] {
		t.Fatalf("the renewed chain must be a contact: %v", got)
	}
	if c := alina.contact(bharat.rootFpr()); string(c.Leaf) != string(bharat.leaf()) {
		t.Fatal("alina's pin must follow the renewal seen on the transport path")
	}

	// The superseded chain — a former host's leaf, still valid — is a guest:
	// the listing shows guest tools only and a contact tool is refused as
	// blocked_or_unknown, exactly as the sealed path answers it.
	old := clientFor(ren.OldKP)
	if got := names(old); got["send_message"] || !got["request_contact"] {
		t.Fatalf("a superseded chain must be listed as a guest: %v", got)
	}
	r, err := old.Call(ctx, peerA, nil, "send_message", map[string]any{"msg_id": "stale-1", "text": "from the old leaf"}, "stale-1")
	if err != nil || !r.IsError || !strings.Contains(textOf(r), "blocked_or_unknown") {
		t.Fatalf("a superseded chain must not send: %v %s", err, textOf(r))
	}
	if alina.received("from the old leaf") {
		t.Fatal("the old leaf's message must not have landed")
	}

	// Another address under `ask`: nothing runs until the owner decides —
	// every call answers pending_approval, the update_contact that brought
	// the address answers pending, and the pin does not move.
	if err := alina.st.SetAccountHostPolicy(ctx, alina.acct.ID, "ask", true); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	moved := identity.EndpointFor("https://bharat-2.test", bharat.slug)
	bharat.install(identity.PurposeMove, moved, 365, clock.now())
	mover := clientFor(bharat.kp())
	r, err = mover.Call(ctx, peerA, nil, "send_message", map[string]any{"msg_id": "moved-1", "text": "from the new address"}, "moved-1")
	if err != nil || !r.IsError || !strings.Contains(textOf(r), "pending_approval") {
		t.Fatalf("a call from an unapproved address: %v %s\n%s", err, textOf(r), strings.Join(alina.log, "\n"))
	}
	r, err = mover.Call(ctx, peerA, nil, "update_contact", map[string]any{"card": bharat.card()}, "moved-2")
	if err != nil || r.IsError || !strings.Contains(textOf(r), `"pending"`) {
		t.Fatalf("update_contact from an unapproved address: %v %s", err, textOf(r))
	}
	if ps, _ := alina.st.ListPendingAddresses(ctx, alina.acct.ID); len(ps) != 1 || ps[0].Endpoint != moved {
		t.Fatalf("the owner must be asked: %+v", ps)
	}
	if c := alina.contact(bharat.rootFpr()); c.Endpoint == moved {
		t.Fatal("under ask the pin must not move until the owner answers")
	}
	if got := names(mover); got["send_message"] {
		t.Fatalf("an unapproved address must be listed as a guest: %v", got)
	}
}

// textOf is the first text content of a tool result, "" when there is none.
func textOf(r *mcp.CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	if tc, ok := r.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
