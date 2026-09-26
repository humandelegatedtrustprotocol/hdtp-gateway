package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/images"
)

// Messaging has to work in BOTH directions after pairing.
//
// It did not. Accepting somebody's invite records them as a contact and grants
// them nothing on your own node — deliberately, since an invite must not choose
// its own privileges on the machine that redeems it — but nothing then asked the
// owner what to grant, so the peer was permanently `permission_denied`. The owner
// saw "error sending" from a relationship that looked established on both sides.
func TestMessagingWorksBothWaysAfterPairing(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := fabricFor(t, "pact2way")
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// seal REQUIRED, which is what edge mode forces (SPEC §10.1) and therefore
	// what every Cloudflare/ngrok deployment runs. A message that arrives
	// promptly unsealed and needs a retry when sealed is a different bug.
	env := map[string]string{"PACT_SEAL": "required"}
	alice, err := StartOwnedNode(ctx, f, images.Node, net, "alice", "18680",
		"https://pact2way-alice:8443", env)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := StartOwnedNode(ctx, f, images.Node, net, "bob", "18681",
		"https://pact2way-bob:8443", env)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	// Bob invites; alice accepts. Auto-accept, so nobody has to approve — this is
	// the shortest path to "we are contacts" and the one an owner will take.
	inviteRaw, err := bob.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": bob.AccountID, "label": "for alice", "max_uses": 1,
		"auto_accept": true, "preset": "friend",
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var inv struct{ Token, URL string }
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.URL == "" {
		inv.URL = "https://" + bob.Node.Name + ":8443/i/" + inv.Token
	}
	addRaw, err := alice.Owner.Call(ctx, "add_contact", map[string]any{
		// No grant named on purpose: accepting an invite must leave them able to
		// reply by default. Naming one is how an owner narrows or refuses it.
		"account_id": alice.AccountID, "invite_url": inv.URL,
	})
	if err != nil {
		t.Fatalf("add_contact: %v", err)
	}
	var added struct{ Fingerprint, Status, Code, Detail string }
	_ = json.Unmarshal([]byte(addRaw), &added)
	if added.Code != "" {
		t.Fatalf("add_contact refused: %s — %s", added.Code, added.Detail)
	}

	// A CONVERSATION, not one message each way: several turns, and every one of
	// them must still be there afterwards. Leaving thread_id empty starts a new
	// thread per message, so the history fragmented into single-message threads
	// and the view — which read the newest thread — showed exactly one line.
	turns := []struct {
		from, to *Owned
		body     string
	}{
		{alice, bob, "first from alice " + PlaintextCanary},
		{bob, alice, "first from bob " + PlaintextCanary},
		{alice, bob, "second from alice " + PlaintextCanary},
		{bob, alice, "second from bob " + PlaintextCanary},
	}
	for i, turn := range turns {
		sendAndExpectAs(ctx, t, turn.from, turn.to, turn.body, fmt.Sprintf("turn-%d", i))
	}

	// Both sides must be able to read the WHOLE exchange back.
	for _, side := range []*Owned{alice, bob} {
		for _, turn := range turns {
			if !conversationContains(ctx, t, side, turn.body) {
				t.Errorf("%s cannot see %q — the history does not survive", side.Node.Name, turn.body)
			}
		}
	}

	// And in the CONVERSATION VIEW, which is where an owner actually reads it — and where the
	// fragmentation showed, because it rendered one thread and every message had started its own.
	//
	// The view is a page over `GET /api/conversations?contact=…`, read as the signed-in owner.
	// This used to fetch `/messages?contact=…` as nobody and look for the text in the HTML; the
	// portal is a single page now and requires a session on every bind, so that fetch returned
	// an application shell with no message in it, for every message, on both sides.
	for _, side := range []struct {
		node *Owned
		peer string
	}{{alice, bob.Fpr}, {bob, alice.Fpr}} {
		code, view, err := side.node.Portal.Get(ctx, "/api/conversations?account="+
			url.QueryEscape(side.node.AccountID)+"&contact="+url.QueryEscape(side.peer))
		if err != nil || code != 200 {
			t.Fatalf("%s's conversation view answered %d (%v): %s", side.node.Node.Name, code, err, shorten(view, 200))
		}
		for _, turn := range turns {
			if !strings.Contains(view, turn.body) {
				t.Errorf("%s's conversation view is missing %q — history is not shown",
					side.node.Node.Name, turn.body)
			}
		}
	}
}

// conversationContains reports whether a node's stored history holds a message.
func conversationContains(ctx context.Context, t *testing.T, o *Owned, body string) bool {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "get_inbox", map[string]any{"account_id": o.AccountID})
	if err != nil {
		return false
	}
	if strings.Contains(raw, body) {
		return true
	}
	var threads []struct {
		ThreadID string `json:"thread_id"`
		ID       string `json:"id"`
	}
	_ = json.Unmarshal([]byte(raw), &threads)
	for _, th := range threads {
		id := th.ThreadID
		if id == "" {
			id = th.ID
		}
		got, err := o.Owner.Call(ctx, "read_thread", map[string]any{
			"account_id": o.AccountID, "thread_id": id})
		if err == nil && strings.Contains(got, body) {
			return true
		}
	}
	return false
}

// sendAndExpectAs sends one message under a given id and requires it to arrive.
func sendAndExpectAs(ctx context.Context, t *testing.T, from, to *Owned, body, msgID string) {
	t.Helper()
	if _, err := from.Owner.Call(ctx, "send_to_contact", map[string]any{
		"account_id": from.AccountID, "contact_fpr": to.Fpr,
		"text": body, "msg_id": msgID,
	}); err != nil {
		t.Fatalf("%s → %s: send refused outright: %v", from.Node.Name, to.Node.Name, err)
	}
	// PROMPT, not eventual. The retry loop will deliver a message a minute later
	// and that is not the same thing: the owner is shown an error, the message
	// sits marked undelivered, and a conversation cannot be had at that speed.
	// A direct send between two reachable nodes has no reason to need a retry.
	started := time.Now()
	if err := waitInbox(ctx, to, body, 20*time.Second); err != nil {
		t.Errorf("%s → %s did not arrive promptly (%v): %v",
			from.Node.Name, to.Node.Name, time.Since(started).Round(time.Second), err)
	}
}

var _ = strings.TrimSpace
