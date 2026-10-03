package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// HDTP §3 and §13.4: a card's X-HDTP-SEAL is the recipient's policy, and a card with no such line
// says `none` — "senders MUST NOT seal". The node read an absent line as `required`, so a recipient
// that left the line out was sent a sealed_call it had said it would not take, and could not be
// reached at all: a node at `none` has no sealed_call on its surface and answers it
// permission_denied, in plaintext, which the sender then discards as not the peer's answer.
//
// Bharat's node does not accept envelopes, and the card Alina holds for him has no X-HDTP-SEAL
// line, as hdtp-identity's EncodeCard writes it for a seal of "". Alina's message must go to him
// in plaintext and arrive; the control is the same message to the card his node serves, which
// says `none` in so many words, and which the node read correctly before.
func TestACardWithNoSealLineIsCalledInPlaintext(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNodeSealed(t, clock, dn, "bharat", "Bharat Mehta", 365, core.SealNone)
	bharat.pinPeer(alina)

	absent, err := hdtpidentity.EncodeCard("Bharat Mehta", bharat.leaf(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(absent, "X-HDTP-SEAL") {
		t.Fatalf("the card under test must carry no X-HDTP-SEAL line:\n%s", absent)
	}
	if served := bharat.card(); !strings.Contains(served, "X-HDTP-SEAL:none") {
		t.Fatalf("bharat's node must serve a card that says none:\n%s", served)
	}
	// Sequential, not subtests: alina.send fails the test it was started under.
	for _, tc := range []struct{ name, card, msgID string }{
		{"X-HDTP-SEAL:none (the control)", bharat.card(), "none-1"},
		{"no X-HDTP-SEAL line", absent, "absent-1"},
	} {
		_ = alina.st.DeleteContact(ctx, alina.acct.ID, bharat.rootFpr())
		if _, err := alina.st.InsertContact(ctx, store.Contact{
			AccountID: alina.acct.ID, Fingerprint: bharat.rootFpr(), SPKI: bharat.leafSPKI(), Status: "active",
			Permissions: []string{"message.text"}, DisplayName: "Bharat Mehta", Card: tc.card,
			Endpoint: bharat.endpoint(), Leaf: bharat.leaf(), PinnedAt: clock.now().Unix(),
		}); err != nil {
			t.Fatal(err)
		}
		bharat.log = nil
		text := "hello bharat, " + tc.msgID
		alina.send(bharat, bharat.rootFpr(), tc.msgID, text)
		if !bharat.received(text) {
			t.Fatalf("%s: bharat did not receive %q", tc.name, text)
		}
		for _, line := range bharat.log {
			if strings.Contains(line, "sealed_call") {
				t.Fatalf("%s: a recipient whose card does not ask for sealing was sent a sealed_call: %s", tc.name, line)
			}
		}
	}
}

// The policy the node reads off the card it holds for a contact, for every card there can be: the
// three values as written, no line (none), a card on file that does not read (refused: its policy is
// not known, and neither guess is safe on the wire), and no card on file at all — a contact that
// arrived in an export, which carries no card (HDTP §9.2), or a returned root the owner approved
// (contacts.DecideAddress) — which is sealed to, as it always was.
func TestAContactsSealIsWhatItsCardOnFileSays(t *testing.T) {
	clock := &demoClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	card := func(seal string) string {
		c, err := hdtpidentity.EncodeCard("Bharat Mehta", bharat.leaf(), seal, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, tc := range []struct {
		name, card, want string
	}{
		{"no X-HDTP-SEAL line", card(""), "none"},
		{"none", card("none"), "none"},
		{"optional", card("optional"), "optional"},
		{"required", card("required"), "required"},
		{"no card on file", "", "required"},
		{"a card with no certificate", "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Bharat\r\nX-HDTP-VERSION:1\r\nEND:VCARD\r\n", ""},
		{"text that is not a card", "not a card", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := alina.n.PeerOf(alina.acct.ID, store.Contact{
				Fingerprint: bharat.rootFpr(), Card: tc.card, Endpoint: bharat.endpoint(), Leaf: bharat.leaf(),
			})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("a card on file that does not read was given the policy %q", peer.Seal)
				}
				if !strings.Contains(err.Error(), bharat.rootFpr()) {
					t.Fatalf("the refusal must name the contact: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if peer.Seal != tc.want {
				t.Fatalf("seal = %q, want %q", peer.Seal, tc.want)
			}
		})
	}
}

// A contact that arrived in an export has no card on file (contacts.csv carries none, HDTP §9.2),
// and it can be written to: the pin is the address and the key. Delivery refused it as "that
// contact's card is unreadable" — parsing the card for nothing but a field it then overwrote with
// the pin's endpoint.
func TestAnImportedContactWithNoCardOnFileCanBeWritten(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	bharat.pinPeer(alina)
	if err := alina.st.ImportContact(ctx, store.Contact{
		AccountID: alina.acct.ID, Fingerprint: bharat.rootFpr(), SPKI: bharat.leafSPKI(), Status: "active",
		Permissions: []string{"message.text"}, TrustFlag: "messages_only", DisplayName: "Bharat Mehta",
		Endpoint: bharat.endpoint(), Leaf: bharat.leaf(), RootCert: bharat.rc, EverActive: true, HandshakeDueAt: clock.now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if c := alina.contact(bharat.rootFpr()); c.Card != "" {
		t.Fatalf("an imported contact must hold no card: %q", c.Card)
	}
	alina.send(bharat, bharat.rootFpr(), "imported-1", "hello bharat, from the import")
	if !bharat.received("hello bharat, from the import") {
		t.Fatal("bharat did not receive the message")
	}
}
