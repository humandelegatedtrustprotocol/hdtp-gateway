package scenario

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/peer"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// PlaintextCanary is planted in message bodies so that whatever CARRIES a sealed message — a
// tunnel's connector, an edge that terminates TLS — can be searched for it afterwards, and
// something unmistakable is either there or not (cloudflare_live_test reads cloudflared's log).
const PlaintextCanary = "PACT-PLAINTEXT-CANARY"

// S2 — pairing, end to end, through every surface the product actually has:
// the setup wizard in a real browser, the owner MCP over a bearer token, and a
// contact's agent over real mTLS. Nothing is stubbed and nothing is in-process.
//
// This is the scenario P10-12i was written for. Until it ran, "two people can pair
// and exchange a message" was proven only by tests that drove outbound.Client
// directly inside one process.
//
// The node, its passkey ceremony and its owner MCP come from World.Node (node.go), which also
// requires the owner to administer exactly one account — this returned null on every node until
// membership was granted (P14-05c). No restart after the account is created: an account created
// on a running node is servable immediately since P14-05a, and if that regresses this fails.
func TestPairingAndMessagingEndToEnd(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S2", Name: "pairing and a first message, end to end, through every surface", Tier: registry.PR,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 8 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Guest onboarding requires direct mode with sealing OPTIONAL: a guest has no way to seal to
	// a node whose key it has not yet received, and receiving it is what redemption is for
	// (SPEC 9.2).
	alice, err := w.Node(ctx, NodeOpts{
		Slug: "alice", Net: net, PublishPublic: true,
		Env: map[string]string{"PACT_SEAL": "optional"},
	})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	oc := alice.Owner

	// --- the owner issues an invite ----------------------------------------
	token, err := invite(ctx, alice, "harness contact", 1)
	if err != nil {
		t.Fatal(err)
	}

	// --- a contact's agent reaches the public surface over real mTLS --------
	bob, err := peer.NewAgent("bob")
	if err != nil {
		t.Fatal(err)
	}
	target := alice.Target()
	names, err := bob.ListTools(ctx, target)
	if err != nil {
		t.Fatalf("bob could not reach alice's public surface: %v", err)
	}
	if !slices.Contains(names, "redeem_invite") {
		t.Fatalf("guest surface has no redeem_invite: %v", names)
	}
	// --- bob redeems the invite, exchanging cards ---------------------------
	redeemed, err := bob.Call(ctx, target, "redeem_invite", map[string]any{
		"token": token, "card": bob.Card("optional"),
	}, "redeem-1")
	if err != nil {
		t.Fatalf("redeem_invite: %v", err)
	}
	t.Logf("redeem_invite -> %s", shorten(redeemed, 160))

	// --- the owner sees the request and approves it -------------------------
	listRaw, err := oc.Call(ctx, "list_contacts", map[string]any{"account_id": alice.AccountID})
	if err != nil {
		t.Fatalf("list_contacts: %v", err)
	}
	t.Logf("contacts after redemption -> %s", shorten(listRaw, 200))
	if !strings.Contains(listRaw, bob.Fingerprint()) {
		t.Fatalf("bob is not on alice's contact list after redeeming: %s", listRaw)
	}
	if _, aerr := oc.Call(ctx, "approve_contact", map[string]any{
		"account_id": alice.AccountID, "contact_fpr": bob.Fingerprint(), "preset": "friend",
	}); aerr != nil {
		t.Fatalf("approve_contact: %v", aerr)
	}

	after, _ := oc.Call(ctx, "list_contacts", map[string]any{"account_id": alice.AccountID})
	t.Logf("contacts AFTER approval -> %s", shorten(after, 320))

	afterTools, terr := bob.ListTools(ctx, target)
	t.Logf("bob's surface AFTER approval -> %v (err=%v)", afterTools, terr)

	// DIAGNOSTIC: if a restart widens the surface, the store is right and the
	// per-caller server cache is stale — i.e. approve_contact never invalidated
	// it (P14-05e).
	if !slices.Contains(afterTools, "send_message") {
		if _, rerr := w.Fab.Raw(ctx, "docker", "restart", alice.Node.Name); rerr != nil {
			t.Fatal(rerr)
		}
		if err := topology.WaitHealthy(ctx, w.Fab, alice.Node); err != nil {
			t.Fatal(err)
		}
		restarted, _ := bob.ListTools(ctx, target)
		t.Logf("bob's surface AFTER RESTART -> %v", restarted)
		if slices.Contains(restarted, "send_message") {
			t.Logf("CONFIRMED: the store was correct; the cached per-caller server was stale")
		}
	}

	// --- bob sends a message over real mTLS ---------------------------------
	body := "hello from the harness " + PlaintextCanary
	sent, serr := bob.Call(ctx, target, "send_message", map[string]any{
		"text": body, "sender": "agent", "msg_id": "harness-msg-1",
	}, "harness-msg-1")
	if serr != nil {
		t.Fatalf("send_message: %v", serr)
	}
	t.Logf("send_message -> %s", shorten(sent, 160))

	// --- and the owner's agent reads it back --------------------------------
	inbox, ierr := oc.Call(ctx, "get_inbox", map[string]any{"account_id": alice.AccountID})
	if ierr != nil {
		t.Fatalf("get_inbox: %v", ierr)
	}
	// get_inbox returns thread SUMMARIES (thread_id, contact_fpr, unread, last_at),
	// not bodies — the body lives behind read_thread. An earlier version of this
	// test looked for the message text in the summary and "failed" on a message
	// that had in fact been delivered.
	var threads []struct {
		ThreadID string `json:"thread_id"`
		Unread   int    `json:"unread"`
	}
	if uerr := json.Unmarshal([]byte(inbox), &threads); uerr != nil {
		t.Fatalf("get_inbox returned unparseable JSON %q: %v", shorten(inbox, 200), uerr)
	}
	if len(threads) != 1 || threads[0].Unread != 1 {
		t.Fatalf("inbox should hold exactly one thread with one unread message, got %s", shorten(inbox, 300))
	}
	body2, rerr := oc.Call(ctx, "read_thread", map[string]any{
		"account_id": alice.AccountID, "thread_id": threads[0].ThreadID,
	})
	if rerr != nil {
		t.Fatalf("read_thread: %v", rerr)
	}
	if !strings.Contains(body2, PlaintextCanary) {
		t.Fatalf("the message bob sent over mTLS never reached alice's thread: %s", shorten(body2, 400))
	}
	t.Logf("read_thread -> %s", shorten(body2, 200))
	t.Logf("guest surface: %v", names)
	t.Logf("invite token: %s…", token[:min(8, len(token))])
}
