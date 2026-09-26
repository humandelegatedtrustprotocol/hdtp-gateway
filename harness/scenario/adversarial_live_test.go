package scenario

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/peer"
)

// S9 — the refusals, probed from OUTSIDE the process against a real node.
//
// Every one of these is unit-tested somewhere in internal/. What was never
// checked is that the shipped binary, reached over a real socket with real
// certificates, refuses them too — which is the only form of the claim that
// matters to somebody running this.
func TestAdversarialProbesAreRefused(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactadv", Ports{Owner: "18611", Public: "18612"}, images.Node)
	t.Cleanup(func() { p.Teardown("") })
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	t.Run("a stranger cannot send a message", func(t *testing.T) {
		// A fresh identity the node has never seen. Guest tier exposes exactly
		// redeem_invite, request_contact and sealed_call (§6.2, §13).
		mallory, err := peer.NewAgent("mallory")
		if err != nil {
			t.Fatal(err)
		}
		names, err := mallory.ListTools(ctx, p.Target)
		if err != nil {
			t.Fatalf("mallory could not reach the node at all: %v", err)
		}
		if contains(names, "send_message") {
			t.Fatalf("an unknown identity was offered send_message: %v", names)
		}
		_, callErr := mallory.Call(ctx, p.Target, "send_message",
			map[string]any{"text": "intrusion", "sender": "agent", "msg_id": "m-int"}, "m-int")
		if callErr == nil {
			t.Fatal("a stranger's send_message was ACCEPTED — tier resolution is broken")
		}
		// §12: a guest-tier refusal is deliberately indistinguishable, so it
		// leaks nothing about whether the contact or account exists.
		if !strings.Contains(callErr.Error(), "blocked_or_unknown") {
			t.Errorf("refusal was %v, want the guest-tier catch-all blocked_or_unknown", callErr)
		}
	})

	t.Run("a contact cannot exceed its granted permissions", func(t *testing.T) {
		// Narrow bob to text only, then try a capability the preset dropped.
		if _, err := p.Owner.Call(ctx, "set_permissions", map[string]any{
			"account_id": p.AccountID, "contact_fpr": p.Contact.Fingerprint(),
			"permissions": []string{"message.text"}, "preset": "custom",
		}); err != nil {
			t.Fatalf("set_permissions: %v", err)
		}
		names, err := p.Contact.ListTools(ctx, p.Target)
		if err != nil {
			t.Fatal(err)
		}
		// The switchboard is enforced in tools/list, not only at call time
		// (§5.4) — so a narrowed contact should not even SEE book_slot.
		if contains(names, "book_slot") {
			t.Errorf("a contact narrowed to message.text still sees book_slot: %v", names)
		}
		if !contains(names, "send_message") {
			t.Errorf("narrowing removed the permission it was supposed to keep: %v", names)
		}
		// And calling it anyway is refused, not merely hidden.
		if _, err := p.Contact.Call(ctx, p.Target, "book_slot",
			map[string]any{"start": "2027-01-01T10:00:00Z", "msg_id": "b-1"}, "b-1"); err == nil {
			t.Error("book_slot succeeded for a contact without calendar.book")
		}
	})

	t.Run("the audit chain stays intact through every refusal", func(t *testing.T) {
		// SPEC §5.8 requires every deny to be audited. The chain must still
		// verify afterwards — a node that breaks its own chain while logging
		// refusals would destroy the evidence it was collecting.
		if _, err := p.Fab.Raw(ctx, "docker", "stop", p.Node.Name); err != nil {
			t.Fatal(err)
		}
		out, err := p.Fab.Raw(ctx, "docker", "run", "--rm", "--volumes-from", p.Node.Name,
			images.Node, "audit", "verify")
		text := strings.TrimSpace(string(out))
		if err != nil || !strings.Contains(text, "intact") {
			t.Fatalf("audit chain not intact after the probes: %v (%s)", err, text)
		}
		t.Logf("audit: %s", text)
		if _, err := p.Fab.Raw(ctx, "docker", "start", p.Node.Name); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
	})
}
