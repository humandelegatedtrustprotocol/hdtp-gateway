package outbound

// What an identity sends is budgeted (HDTP §12's buckets, applied outbound): every call out passes
// Budget once, before anything is dialled, and a refusal is RateLimited with its wait — nothing
// leaves the host.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

func TestEveryCallOutPassesTheBudgetOnceAndARefusalDialsNothing(t *testing.T) {
	h := testid.NewWallet(t, "Peer").Issue(t, "https://peer.example/mcp")
	sealed := Peer{Endpoint: h.Endpoint, Seal: "required", Root: h.RootFpr, Leaf: h.LeafDER}
	plain := Peer{Endpoint: h.Endpoint, Seal: "none", Root: h.RootFpr, Leaf: h.LeafDER}
	dialled := 0
	var spent []string
	refuse := true
	c := newTestIdentity(t, "Me", "https://me.example/mcp").client()
	*c = Client{
		Keypair: c.Keypair, Cert: c.Cert,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialled++
			return nil, errors.New("no network here")
		},
		Budget: func(p Peer, tool string) error {
			spent = append(spent, tool)
			if refuse {
				return &RateLimited{RetryAfter: 7 * time.Second}
			}
			return nil
		},
	}
	ctx := context.Background()
	check := func(what string, err error, tool string) {
		t.Helper()
		var rl *RateLimited
		if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
			t.Fatalf("%s: %v, want RateLimited after 7 s", what, err)
		}
		if len(spent) != 1 || spent[0] != tool {
			t.Fatalf("%s spent %v, want once as %q", what, spent, tool)
		}
		spent = nil
	}
	_, err := c.Call(ctx, sealed, "send_message", map[string]any{}, "m1")
	check("a sealed call", err, "send_message")
	_, err = c.Call(ctx, plain, "send_message", map[string]any{}, "m2")
	check("a plaintext call", err, "send_message")
	_, err = c.SealedListTools(ctx, sealed, "m3")
	check("a sealed tools/list", err, "tools/list")
	_, err = c.ListTools(ctx, plain)
	check("a plaintext tools/list", err, "tools/list")
	if dialled != 0 {
		t.Fatalf("%d dials for calls the budget refused", dialled)
	}
	// Let through, a sealed call spends once as its tool — the `sealed_call` wrapper that carries
	// it on the wire is the same call, not a second one.
	refuse = false
	_, _ = c.Call(ctx, sealed, "send_message", map[string]any{}, "m5")
	if len(spent) != 1 || spent[0] != "send_message" || dialled == 0 {
		t.Fatalf("a sealed call let through spent %v (dialled %d), want once as send_message", spent, dialled)
	}
}
