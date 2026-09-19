package contacts

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

import "github.com/tech-sumit/pact-gateway/internal/core/store"

// newInitEnv and peerCard reuse the existing manager-test helpers so the two
// suites cannot drift on what a card or a keypair looks like.
func newInitEnv(t *testing.T) (*Manager, *store.SQLite, context.Context, string) {
	t.Helper()
	e := newEnv(t)
	return e.m, e.st, context.Background(), e.account
}

func peerCard(t *testing.T, name string) (card, fpr string, spki []byte) {
	t.Helper()
	kp, c, s := guest(t, name)
	return c, kp.Fingerprint, s
}

// SPEC §9's contact state machine has a transition nothing could take:
//
//	none --> pending_out : owner redeems a non-auto_accept invite / sends request_contact
//
// `pending_out` existed as a status and as a policy tier, and ContactAccepted and
// ContactRejected both REQUIRE a row in it — but nothing in the product ever wrote
// one. So the owner-initiated half of contact establishment was unreachable, which
// is why a node could only ever hold agents that had called IN as contacts, never
// a peer it reached out to (E16).
func TestInitiatedRecordsAnOwnerStartedContact(t *testing.T) {
	m, st, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Bob")

	if err := m.Initiated(ctx, acct, fpr, card, spki, false, nil); err != nil {
		t.Fatalf("Initiated: %v", err)
	}
	c, err := st.GetContact(ctx, acct, fpr)
	if err != nil {
		t.Fatalf("no contact row was written: %v", err)
	}
	if c.Status != "pending_out" {
		t.Errorf("status is %q, want pending_out — the peer has not accepted yet", c.Status)
	}
	if string(c.SPKI) != string(spki) {
		t.Error("the peer's key was not pinned, so nothing later can verify them")
	}
	if c.DisplayName != "Bob" {
		t.Errorf("display name %q", c.DisplayName)
	}
	// and the transition that was previously unreachable now works end to end
	if err := m.ContactAccepted(ctx, acct, fpr, card, []string{"message.text"}); err != nil {
		t.Fatalf("ContactAccepted still cannot find a pending_out row: %v", err)
	}
	c, _ = st.GetContact(ctx, acct, fpr)
	if c.Status != "active" {
		t.Errorf("after acceptance the contact is %q, want active", c.Status)
	}
}

// An invite that auto-accepts tells us so in its response; the contact is active
// immediately and there is nothing for the peer to approve.
func TestInitiatedHonoursAnAutoAcceptedInvite(t *testing.T) {
	m, st, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Ann")
	if err := m.Initiated(ctx, acct, fpr, card, spki, true, []string{"message.text"}); err != nil {
		t.Fatal(err)
	}
	c, _ := st.GetContact(ctx, acct, fpr)
	if c.Status != "active" {
		t.Errorf("an auto-accepted redemption left the contact %q", c.Status)
	}
	// What the peer granted US goes in TheirPermissions. Permissions is what WE
	// grant THEM, and an invite must not be able to choose its own privileges on
	// the node that redeemed it.
	if len(c.TheirPermissions) != 1 || c.TheirPermissions[0] != "message.text" {
		t.Errorf("the permissions the peer granted us were dropped: %v", c.TheirPermissions)
	}
	if len(c.Permissions) != 0 {
		t.Errorf("redeeming an invite granted the peer %v on OUR node; an invite must "+
			"not choose its own privileges here", c.Permissions)
	}
}

// The pin is the whole of identity (PACT §2), so it must not be possible to
// record a contact whose pinned key is not the key its card claims — that would
// let a tampered invite bind us to an attacker's key under the peer's name.
func TestInitiatedRefusesAKeyThatDoesNotMatchTheCard(t *testing.T) {
	m, _, ctx, acct := newInitEnv(t)
	card, fpr, _ := peerCard(t, "Bob")
	_, _, otherSPKI := peerCard(t, "Mallory")

	err := m.Initiated(ctx, acct, fpr, card, otherSPKI, false, nil)
	if err == nil {
		t.Fatal("a contact was pinned to a key that is not the card's X-PACT-KEY")
	}
	if !errors.Is(err, ErrIdentityRequired) {
		t.Errorf("wrong error class: %v", err)
	}
}

func TestInitiatedRefusesAFingerprintThatDoesNotMatchTheCard(t *testing.T) {
	m, _, ctx, acct := newInitEnv(t)
	card, _, spki := peerCard(t, "Bob")
	err := m.Initiated(ctx, acct, "sha256:not-the-card-key", card, spki, false, nil)
	if err == nil || !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("a mismatched fingerprint was accepted: %v", err)
	}
}

// Initiating twice must not silently overwrite an existing relationship — in
// particular it must not be a way to reset a BLOCKED contact back to pending.
func TestInitiatedDoesNotOverwriteAnExistingContact(t *testing.T) {
	m, _, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Bob")
	if err := m.Initiated(ctx, acct, fpr, card, spki, false, nil); err != nil {
		t.Fatal(err)
	}
	err := m.Initiated(ctx, acct, fpr, card, spki, false, nil)
	if err == nil {
		t.Fatal("a second initiation overwrote the existing contact row")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error should say the contact is already known: %v", err)
	}
}

// The request_contact path holds the peer's card but not their key. The row is
// pinned to the ROOT the card's certificate names; the leaf and its key arrive
// with the first chain that validates (PACT §14.3). This used to end in BindSPKI,
// which recorded the key when a rotation had left the row fingerprint-only — a
// state 2.0 cannot produce.
func TestInitiatedByFingerprintPinsTheNameAndTheRoot(t *testing.T) {
	m, st, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Bob")
	if err := m.InitiatedByFingerprint(ctx, acct, fpr, card); err != nil {
		t.Fatal(err)
	}
	c, err := st.GetContact(ctx, acct, fpr)
	if err != nil {
		t.Fatalf("no contact row: %v", err)
	}
	if c.Status != "pending_out" {
		t.Errorf("status=%q, want pending_out", c.Status)
	}
	// This asserted the OPPOSITE — "want pending_out with no key yet" — on the reasoning that a
	// card carries only a key's hash and the key arrives later. A 2.0 card carries the leaf, the
	// key is in it, and the pin is incomplete without it.
	if !bytes.Equal(c.SPKI, spki) {
		t.Errorf("the pin holds %d bytes of key, want the %d-byte key in the card's own certificate", len(c.SPKI), len(spki))
	}
	if len(c.Leaf) == 0 || c.Endpoint == "" {
		t.Errorf("the pin is missing its leaf or its address: leaf=%d bytes endpoint=%q", len(c.Leaf), c.Endpoint)
	}
	if c.DisplayName != "Bob" {
		t.Errorf("display name = %q, want Bob", c.DisplayName)
	}
}

// The consequence the missing key had, walked end to end: we send `request_contact`, the peer
// accepts, and the contact is ACTIVE — and must still be sealable. `contact_accepted` writes the
// card and the grant and never touched the key, and a chain presenting the same leaf re-pins
// nothing (PACT §14.3), so a key not stored at the start was never stored at all. Every later call
// then went plaintext to a `seal: optional` peer and failed outright to a `required` one.
func TestAContactWeRequestedIsSealableOnceTheyAccept(t *testing.T) {
	m, st, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Bob")
	if err := m.InitiatedByFingerprint(ctx, acct, fpr, card); err != nil {
		t.Fatal(err)
	}
	if err := m.ContactAccepted(ctx, acct, fpr, card, []string{"message.text"}); err != nil {
		t.Fatal(err)
	}
	c, err := st.GetContact(ctx, acct, fpr)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "active" {
		t.Fatalf("status=%q, want active", c.Status)
	}
	if !bytes.Equal(c.SPKI, spki) {
		t.Fatalf("an accepted contact holds %d bytes of key: there is nothing to seal to, so calls to it "+
			"downgrade to plaintext or fail", len(c.SPKI))
	}
}

func TestInitiatedByFingerprintRefusesACardThatNamesAnotherKey(t *testing.T) {
	m, _, ctx, acct := newInitEnv(t)
	card, _, _ := peerCard(t, "Bob")
	if err := m.InitiatedByFingerprint(ctx, acct, "sha256:someone-else", card); err == nil ||
		!errors.Is(err, ErrIdentityRequired) {
		t.Fatal("a card was recorded under a fingerprint it does not claim")
	}
}
