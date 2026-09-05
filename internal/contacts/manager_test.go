package contacts

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

type env struct {
	m       *Manager
	st      *store.SQLite
	account string
	clock   *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1756000000, 0)
	return &env{
		m:  &Manager{Store: st, Now: func() time.Time { return clock }},
		st: st, account: a.ID, clock: &clock,
	}
}

// guest makes a keypair and a card claiming that keypair's fingerprint.
func guest(t *testing.T, name string) (*identity.Keypair, string, []byte) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	card := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:" + name + "\r\nX-PACT-VERSION:1\r\nX-PACT-ENDPOINT:https://" + name + ".example/mcp\r\nX-PACT-KEY:" + kp.Fingerprint + "\r\nEND:VCARD\r\n"
	return kp, card, spki
}

func TestRedeemAutoAcceptYieldsActiveContact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	token, _, err := e.m.CreateInvite(ctx, e.account, InviteOptions{
		AutoAccept: true, Preset: "friend", Permissions: []string{"message.text", "calendar.book"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, card, spki := guest(t, "Bharat")
	res, err := e.m.Redeem(ctx, e.account, token, card, CardKey(card), spki)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "accepted" || len(res.Permissions) != 2 {
		t.Fatalf("redeem: %+v", res)
	}
	c, err := e.st.GetContact(ctx, e.account, CardKey(card))
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "active" || c.Preset != "friend" || c.DisplayName != "Bharat" || len(c.SPKI) == 0 {
		t.Fatalf("contact: %+v", c)
	}
}

func TestRedeemWithoutAutoAcceptIsPending(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
	_, card, spki := guest(t, "G")
	res, err := e.m.Redeem(ctx, e.account, token, card, CardKey(card), spki)
	if err != nil || res.Status != "pending" {
		t.Fatalf("%v %+v", err, res)
	}
	c, _ := e.st.GetContact(ctx, e.account, CardKey(card))
	if c.Status != "pending_in" {
		t.Fatalf("status %s", c.Status)
	}
}

func TestRedeemFailures(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	t.Run("unknown token", func(t *testing.T) {
		_, card, spki := guest(t, "G")
		_, err := e.m.Redeem(ctx, e.account, "deadbeef", card, CardKey(card), spki)
		if !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("exhausted", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
		_, c1, s1 := guest(t, "A")
		if _, err := e.m.Redeem(ctx, e.account, token, c1, CardKey(c1), s1); err != nil {
			t.Fatal(err)
		}
		_, c2, s2 := guest(t, "B")
		if _, err := e.m.Redeem(ctx, e.account, token, c2, CardKey(c2), s2); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{TTL: time.Hour})
		*e.clock = e.clock.Add(2 * time.Hour)
		_, card, spki := guest(t, "G")
		if _, err := e.m.Redeem(ctx, e.account, token, card, CardKey(card), spki); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		if err := e.st.RevokeInvite(ctx, inv.ID, e.clock.Unix()); err != nil {
			t.Fatal(err)
		}
		_, card, spki := guest(t, "G")
		if _, err := e.m.Redeem(ctx, e.account, token, card, CardKey(card), spki); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("card/key mismatch", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		_, card, _ := guest(t, "Honest")
		evil, _, evilSPKI := guest(t, "Evil")
		// evil presents its own key but submits Honest's card
		_, err := e.m.Redeem(ctx, e.account, token, card, evil.Fingerprint, evilSPKI)
		if !errors.Is(err, ErrIdentityRequired) {
			t.Fatalf("want identity_required, got %v", err)
		}
	})
	t.Run("ttl cap", func(t *testing.T) {
		if _, _, err := e.m.CreateInvite(ctx, e.account, InviteOptions{TTL: 100 * 24 * time.Hour}); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("91d+ ttl accepted: %v", err)
		}
	})
}

func TestPendingAnswerTools(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	kp, card, spki := guest(t, "Invited")
	// we invited them: pending_out
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: kp.Fingerprint, SPKI: spki,
		Status: "pending_out", Card: card,
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.ContactAccepted(ctx, e.account, kp.Fingerprint, card, nil); err != nil {
		t.Fatal(err)
	}
	c, _ := e.st.GetContact(ctx, e.account, kp.Fingerprint)
	if c.Status != "active" {
		t.Fatalf("status %s", c.Status)
	}
	// a stranger cannot answer an invitation that doesn't exist
	other, _, _ := guest(t, "X")
	if err := e.m.ContactAccepted(ctx, e.account, other.Fingerprint, card, nil); !errors.Is(err, ErrUnknownContact) {
		t.Fatalf("want unknown_contact, got %v", err)
	}
}

func TestUpdateContactVerifiedRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	oldKP, oldCard, oldSPKI := guest(t, "Rotator")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: oldKP.Fingerprint, SPKI: oldSPKI,
		Status: "active", Card: oldCard,
	}); err != nil {
		t.Fatal(err)
	}
	newKP, newCard, newSPKI := guest(t, "Rotator")

	// signature by the OLD key over the NEW fingerprint (PACT §2)
	h := sha256.Sum256([]byte(newKP.Fingerprint))
	sig, err := ecdsa.SignASN1(rand.Reader, oldKP.Signer.(*ecdsa.PrivateKey), h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := e.m.UpdateContact(ctx, e.account, oldKP.Fingerprint, newCard, sig, newSPKI); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.GetContact(ctx, e.account, oldKP.Fingerprint); err == nil {
		t.Fatal("old fingerprint still pinned")
	}
	c, err := e.st.GetContact(ctx, e.account, newKP.Fingerprint)
	if err != nil || c.Status != "active" {
		t.Fatalf("re-pin lost: %v %+v", err, c)
	}

	// a signature by the WRONG key must be refused
	third, thirdCard, thirdSPKI := guest(t, "Third")
	h2 := sha256.Sum256([]byte(third.Fingerprint))
	badSig, _ := ecdsa.SignASN1(rand.Reader, third.Signer.(*ecdsa.PrivateKey), h2[:])
	if err := e.m.UpdateContact(ctx, e.account, newKP.Fingerprint, thirdCard, badSig, thirdSPKI); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("forged rotation accepted: %v", err)
	}
}

func TestRequestContactNoteCapAndBinding(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, card, spki := guest(t, "Asker")
	long := make([]byte, 1025)
	if err := e.m.RequestContact(ctx, e.account, card, string(long), CardKey(card), spki); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("1 KiB note cap not enforced: %v", err)
	}
	if err := e.m.RequestContact(ctx, e.account, card, "hi", CardKey(card), spki); err != nil {
		t.Fatal(err)
	}
	evil, _, evilSPKI := guest(t, "Evil2")
	_, card2, _ := guest(t, "Someone")
	if err := e.m.RequestContact(ctx, e.account, card2, "", evil.Fingerprint, evilSPKI); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("card/key mismatch accepted: %v", err)
	}
}

// AC (P8-01, defect #4): an endpoint announcement repins a contact to its OWN
// fingerprint. If that call proved no key, writing the empty SPKI straight over
// the stored one would leave a contact we could no longer seal to. A genuine key
// change is different: there the new key legitimately binds on first connection.
func TestRepinKeepsThePinnedKeyWhenNoKeyIsProven(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	st, m := e.st, e.m
	acctID := e.account

	kp, _ := identity.Generate(identity.AlgoP256)
	spki, _ := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	oldCard, _ := BuildCard(Card{FN: "Peer", Endpoint: "https://old.example/a/p/mcp", Key: kp.Fingerprint})
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acctID, Fingerprint: kp.Fingerprint, SPKI: spki,
		Status: "active", Card: oldCard, Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}

	// same identity, new endpoint, signed by the key we already pinned — and no
	// key proven on this call
	newCard, _ := BuildCard(Card{FN: "Peer", Endpoint: "https://moved.example/a/p/mcp", Key: kp.Fingerprint})
	sig, err := identity.SignBytes(kp, []byte(kp.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateContact(ctx, acctID, kp.Fingerprint, newCard, sig, nil); err != nil {
		t.Fatalf("endpoint announcement refused: %v", err)
	}
	got, err := st.GetContact(ctx, acctID, kp.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SPKI) == 0 {
		t.Fatal("the repin wiped the pinned key: this contact can no longer be sealed to")
	}
	if !strings.Contains(got.Card, "moved.example") {
		t.Fatalf("the new endpoint was not stored:\n%s", got.Card)
	}

	// a genuine key change still binds the new key when it is proven
	newKP, _ := identity.Generate(identity.AlgoP256)
	newSPKI, _ := x509.MarshalPKIXPublicKey(newKP.Signer.Public())
	rotated, _ := BuildCard(Card{FN: "Peer", Endpoint: "https://moved.example/a/p/mcp", Key: newKP.Fingerprint})
	proof, err := identity.SignBytes(kp, []byte(newKP.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateContact(ctx, acctID, kp.Fingerprint, rotated, proof, newSPKI); err != nil {
		t.Fatalf("rotation refused: %v", err)
	}
	after, err := st.GetContact(ctx, acctID, newKP.Fingerprint)
	if err != nil {
		t.Fatalf("the rotated contact is gone: %v", err)
	}
	if string(after.SPKI) != string(newSPKI) {
		t.Fatal("the rotation did not bind the new key")
	}
}

// AC (P10-09a): the rotation SPEC §3.9 step 3 actually performs must succeed.
//
// TestUpdateContactVerifiedRotation passes the NEW SPKI as the proven key, which
// is not what the wire delivers. §3.9 step 4 is explicit: during the grace period
// "outbound calls to a contact that has not yet re-pinned present the OLD
// certificate", and internal/cli/cli.go builds exactly that client. So the
// receiver sees the old key, and requiring it to hash to the new card rejects
// every real rotation — turning `account rotate` into contact loss.
func TestRotationPresentingTheOldCertificateIsAccepted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	oldKP, oldCard, oldSPKI := guest(t, "Rotator")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: oldKP.Fingerprint, SPKI: oldSPKI,
		Status: "active", Card: oldCard,
	}); err != nil {
		t.Fatal(err)
	}
	newKP, newCard, _ := guest(t, "Rotator")
	h := sha256.Sum256([]byte(newKP.Fingerprint))
	sig, err := ecdsa.SignASN1(rand.Reader, oldKP.Signer.(*ecdsa.PrivateKey), h[:])
	if err != nil {
		t.Fatal(err)
	}

	// The peer calls as its OLD identity — the one our pin recognizes.
	if err := e.m.UpdateContact(ctx, e.account, oldKP.Fingerprint, newCard, sig, oldSPKI); err != nil {
		t.Fatalf("the rotation SPEC §3.9 performs was refused: %v", err)
	}
	c, err := e.st.GetContact(ctx, e.account, newKP.Fingerprint)
	if err != nil || c.Status != "active" {
		t.Fatalf("re-pin lost: %v %+v", err, c)
	}
	// The old key must NOT survive as the pinned SPKI: it is destroyed at grace
	// expiry (§3.9 step 5), and sealing to it after that would be undeliverable.
	if len(c.SPKI) != 0 {
		t.Fatalf("kept a stale SPKI for a key that is about to be destroyed (%d bytes)", len(c.SPKI))
	}

	// A fingerprint-only pin must still support the NEXT rotation: the peer
	// presents the pinned identity, and its certificate supplies the key bytes
	// we no longer store.
	newSPKI, err := x509.MarshalPKIXPublicKey(newKP.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	third, thirdCard, _ := guest(t, "Third")
	h2 := sha256.Sum256([]byte(third.Fingerprint))
	sig2, _ := ecdsa.SignASN1(rand.Reader, newKP.Signer.(*ecdsa.PrivateKey), h2[:])
	if err := e.m.UpdateContact(ctx, e.account, newKP.Fingerprint, thirdCard, sig2, newSPKI); err != nil {
		t.Fatalf("a fingerprint-only pin could not rotate: %v", err)
	}
	if _, err := e.st.GetContact(ctx, e.account, third.Fingerprint); err != nil {
		t.Fatalf("second re-pin lost: %v", err)
	}

	// A third key vouching for a card it does not own is still a lie.
	fourth, fourthCard, fourthSPKI := guest(t, "Fourth")
	h3 := sha256.Sum256([]byte(fourth.Fingerprint))
	badSig, _ := ecdsa.SignASN1(rand.Reader, fourth.Signer.(*ecdsa.PrivateKey), h3[:])
	if err := e.m.UpdateContact(ctx, e.account, third.Fingerprint, fourthCard, badSig, fourthSPKI); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("forged rotation accepted: %v", err)
	}
}

// AC (P10-09b): a contact left fingerprint-only by a rotation binds its key the
// next time that key connects (SPEC §3.9, escalation E7 option B).
//
// Without this the drop to fingerprint-only would be permanent and we could
// never seal to that contact again — which would make E7's choice a bug rather
// than a trade-off.
func TestFingerprintOnlyContactBindsItsKeyOnNextConnection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	kp, card, spki := guest(t, "Rotated")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: kp.Fingerprint, Status: "active", Card: card,
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := e.st.GetContact(ctx, e.account, kp.Fingerprint)
	if len(before.SPKI) != 0 {
		t.Fatal("the fixture is not fingerprint-only")
	}

	if err := e.m.BindSPKI(ctx, e.account, kp.Fingerprint, spki); err != nil {
		t.Fatalf("binding the pinned key failed: %v", err)
	}
	after, _ := e.st.GetContact(ctx, e.account, kp.Fingerprint)
	if string(after.SPKI) != string(spki) {
		t.Fatal("the key was not recorded")
	}
	if after.Card != card {
		t.Fatalf("binding a key rewrote the contact's card: %q", after.Card)
	}

	// A key that does NOT hash to the pin is not that contact's key.
	other, _, otherSPKI := guest(t, "Other")
	_ = other
	if err := e.m.BindSPKI(ctx, e.account, kp.Fingerprint, otherSPKI); err == nil {
		t.Fatal("a key that does not match the pin was bound")
	}
	// Binding again is a no-op, not an error: it happens on every connection.
	if err := e.m.BindSPKI(ctx, e.account, kp.Fingerprint, spki); err != nil {
		t.Fatalf("re-binding an already-bound key failed: %v", err)
	}
}
