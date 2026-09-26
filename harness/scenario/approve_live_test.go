package scenario

import (
	"context"

	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/registry"
)

// Approving a contact must reach the OTHER side.
//
// `contact_accepted` — "Tell me my contact request was accepted" — is a
// pending-tier tool every node has always served, and nothing ever called it. So
// an owner approved a request, watched the contact go active on their own node,
// and the person who asked sat at `pending_out` forever with no way to know. The
// owner saw it as "I accepted them and they still show as pending".
//
// This is the two-sided check: after the approval, BOTH sides say active.
func TestApprovingAContactReachesThePeer(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "S12", Name: "approving a contact reaches the peer: both sides active", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 15 * time.Minute,
	})

	f := fabricFor(t, "pactapp")
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := StartOwnedNode(ctx, f, images.Node, net, "alice", "18670",
		"https://pactapp-alice:8443", map[string]string{"PACT_SEAL": "optional"})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := StartOwnedNode(ctx, f, images.Node, net, "bob", "18671",
		"https://pactapp-bob:8443", map[string]string{"PACT_SEAL": "optional"})
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	// An invite WITHOUT auto-accept: the whole point is the owner deciding later,
	// which is the path that left the peer stranded.
	inviteRaw, err := alice.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": alice.AccountID, "label": "for bob", "max_uses": 1,
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var inv struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.URL == "" {
		inv.URL = "https://" + alice.Node.Name + ":8443/i/" + inv.Token
	}

	addRaw, err := bob.Owner.Call(ctx, "add_contact", map[string]any{
		"account_id": bob.AccountID, "invite_url": inv.URL,
	})
	if err != nil {
		t.Fatalf("add_contact: %v", err)
	}
	var added struct{ Fingerprint, Status, Code, Detail string }
	_ = json.Unmarshal([]byte(addRaw), &added)
	if added.Code != "" {
		t.Fatalf("add_contact refused: %s — %s", added.Code, added.Detail)
	}
	// Not auto-accepted, so this is exactly the state the owner reported.
	if added.Status != "pending_out" {
		t.Fatalf("a non-auto-accept invite left bob at %q, want pending_out", added.Status)
	}

	// Alice approves, as an owner would.
	if _, err := alice.Owner.Call(ctx, "approve_contact", map[string]any{
		"account_id": alice.AccountID, "contact_fpr": bob.Fpr, "preset": "friend",
	}); err != nil {
		t.Fatalf("approve_contact: %v", err)
	}

	// Alice's side is the easy half.
	if got := contactStatus(ctx, t, alice, bob.Fpr); got != "active" {
		t.Errorf("on alice's node bob is %q, want active", got)
	}
	// Bob's side is the one that was broken.
	deadline := time.Now().Add(90 * time.Second)
	for {
		got := contactStatus(ctx, t, bob, alice.Fpr)
		if got == "active" {
			t.Log("both sides active: the approval reached the peer")
			return
		}
		if time.Now().After(deadline) {
			al, _ := f.Raw(ctx, "docker", "logs", alice.Node.Name)
			t.Fatalf("bob still sees alice as %q — the approval never reached him\nalice: %s",
				got, shorten(string(al), 600))
		}
		time.Sleep(3 * time.Second)
	}
}

// contactStatus reads one contact's status through the owner MCP.
func contactStatus(ctx context.Context, t *testing.T, o *Owned, fpr string) string {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "list_contacts", map[string]any{"account_id": o.AccountID})
	if err != nil {
		t.Fatalf("list_contacts: %v", err)
	}
	var rows []struct{ Fingerprint, Status string }
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		// tolerate a wrapped shape
		var wrapped struct {
			Contacts []struct{ Fingerprint, Status string } `json:"contacts"`
		}
		if json.Unmarshal([]byte(raw), &wrapped) == nil {
			rows = wrapped.Contacts
		}
	}
	for _, r := range rows {
		if r.Fingerprint == fpr {
			return r.Status
		}
	}
	if strings.Contains(raw, fpr) {
		return "present-but-unparsed: " + shorten(raw, 160)
	}
	return "absent"
}

// fabricFor builds a fabric that cleans up after the test.
func fabricFor(t *testing.T, prefix string) *fabric.Fabric {
	t.Helper()
	f := fabric.New(prefix, dockerRun)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if dir := os.Getenv("PACT_HARNESS_ARTIFACTS"); dir != "" {
			_ = f.Collect(c, dir)
		}
		_ = f.Teardown(c)
	})
	return f
}
