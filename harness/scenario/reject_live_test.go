package scenario

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/registry"
)

// Rejecting a request must reach the requester, and unblocking a rejected request must let them
// ask again (review N-01, P-13; the plan of record's D1).
//
// The node served `contact_rejected` and never sent it, so a node it rejected sat at
// `pending_out` for ever; and `blocked` had no way out but a silent delete, on no surface an agent
// could reach. This drives both over the owner MCP of two real nodes: bob asks through alice's
// invite, alice rejects, and bob's own node must say alice is blocked — the only way it can know
// is the call. Then alice unblocks (a request never approved is forgotten, not made active), bob
// clears his side, asks again through a fresh invite, and alice sees a waiting request again.
// The control is the second request: it has to land, or a node that refused everything would pass.
func TestRejectingAContactReachesThePeerAndUnblockLetsThemAskAgain(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S13", Name: "a rejection reaches the peer, and an unblock lets them ask again", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 15 * time.Minute,
	})

	f := w.Fab
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net, Env: map[string]string{"PACT_SEAL": "optional"}})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := w.Node(ctx, NodeOpts{Slug: "bob", Net: net, Env: map[string]string{"PACT_SEAL": "optional"}})
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	ask := func(label string) {
		t.Helper()
		raw, err := alice.Owner.Call(ctx, "create_invite", map[string]any{
			"account_id": alice.AccountID, "label": label, "max_uses": 1,
		})
		if err != nil {
			t.Fatalf("create_invite: %v", err)
		}
		var inv struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal([]byte(raw), &inv)
		url := "https://" + alice.Node.Name + ":8443/i/" + inv.Token
		out, err := bob.Owner.Call(ctx, "add_contact", map[string]any{"account_id": bob.AccountID, "invite_url": url})
		if err != nil {
			t.Fatalf("add_contact (%s): %v", label, err)
		}
		var added struct{ Status string }
		_ = json.Unmarshal([]byte(out), &added)
		if added.Status != "pending_out" {
			t.Fatalf("a manual invite left bob at %q (%s), want pending_out", added.Status, shorten(out, 200))
		}
	}
	waitFor := func(o *Owned, fpr, want string, why string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			got := contactStatus(ctx, t, o, fpr)
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %q, want %q", why, got, want)
			}
			time.Sleep(3 * time.Second)
		}
	}

	ask("for bob")
	waitFor(alice, bob.Fpr, "pending_in", "alice never saw bob's request")

	out, err := alice.Owner.Call(ctx, "reject_contact", map[string]any{"account_id": alice.AccountID, "contact_fpr": bob.Fpr})
	if err != nil {
		t.Fatalf("reject_contact: %v", err)
	}
	if !strings.Contains(out, `"told":true`) {
		t.Errorf("alice's node says bob was not told of the rejection: %s", out)
	}
	if got := contactStatus(ctx, t, alice, bob.Fpr); got != "blocked" {
		t.Errorf("a rejected request is %q on alice's node, want blocked (a demotion, not a deletion)", got)
	}
	// The half that was missing: bob's node learns it, from the call alone.
	waitFor(bob, alice.Fpr, "blocked", "bob's node never heard the rejection")

	out, err = alice.Owner.Call(ctx, "unblock_contact", map[string]any{"account_id": alice.AccountID, "contact_fpr": bob.Fpr})
	if err != nil {
		t.Fatalf("unblock_contact: %v", err)
	}
	if !strings.Contains(out, `"status":"none"`) {
		t.Errorf("unblocking a rejected request answered %s; it was never a contact, so it is forgotten", out)
	}
	if got := contactStatus(ctx, t, alice, bob.Fpr); got != "absent" {
		t.Fatalf("after the unblock bob is %q on alice's node, want absent", got)
	}
	// Bob withdraws his own record of the declined approach, and asks again.
	if _, err := bob.Owner.Call(ctx, "remove_contact", map[string]any{"account_id": bob.AccountID, "contact_fpr": alice.Fpr}); err != nil {
		t.Fatalf("bob's remove_contact: %v", err)
	}
	ask("for bob, again")
	waitFor(alice, bob.Fpr, "pending_in", "bob's fresh request after the unblock never reached alice")
}
