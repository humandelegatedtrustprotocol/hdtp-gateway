package contacts

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/testid"
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

// guestID stands in for a peer identity in these tests. Fingerprint is the ROOT
// fingerprint, which is what a contact is pinned by (PACT §2) — not the leaf key,
// which changes at every renewal.
type guestID struct {
	Fingerprint string
	Host        *testid.Host
}

// guest builds a whole peer: a root, a leaf naming an endpoint, and the card that
// carries it. It used to hand back a bare keypair and a `X-PACT-VERSION:1` card
// with the key spelled out; there is no such card now.
func guest(t *testing.T, name string) (*guestID, string, []byte) {
	t.Helper()
	w := testid.NewWallet(t, name)
	h := w.Issue(t, "https://"+name+".example/mcp")
	return &guestID{Fingerprint: w.Fpr, Host: h}, h.Card(name, ""), h.Key.Public.SPKI
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
	res, err := e.m.RedeemAs(ctx, e.account, token, card, Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1})
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
	res, err := e.m.RedeemAs(ctx, e.account, token, card, Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1})
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
		_, err := e.m.RedeemAs(ctx, e.account, "deadbeef", card, Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1})
		if !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("exhausted", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
		_, c1, s1 := guest(t, "A")
		if _, err := e.m.RedeemAs(ctx, e.account, token, c1, Proof{Fingerprint: CardKey(c1), SPKI: s1, Protocol: 1}); err != nil {
			t.Fatal(err)
		}
		_, c2, s2 := guest(t, "B")
		if _, err := e.m.RedeemAs(ctx, e.account, token, c2, Proof{Fingerprint: CardKey(c2), SPKI: s2, Protocol: 1}); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{TTL: time.Hour})
		*e.clock = e.clock.Add(2 * time.Hour)
		_, card, spki := guest(t, "G")
		if _, err := e.m.RedeemAs(ctx, e.account, token, card, Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1}); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		if err := e.st.RevokeInvite(ctx, inv.ID, e.clock.Unix()); err != nil {
			t.Fatal(err)
		}
		_, card, spki := guest(t, "G")
		if _, err := e.m.RedeemAs(ctx, e.account, token, card, Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1}); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("want invite_invalid, got %v", err)
		}
	})
	t.Run("card/key mismatch", func(t *testing.T) {
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		_, card, _ := guest(t, "Honest")
		evil, _, evilSPKI := guest(t, "Evil")
		// evil presents its own key but submits Honest's card
		_, err := e.m.RedeemAs(ctx, e.account, token, card, Proof{Fingerprint: evil.Fingerprint, SPKI: evilSPKI, Protocol: 1})
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

func TestRequestContactNoteCapAndBinding(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, card, spki := guest(t, "Asker")
	long := make([]byte, 1025)
	if err := e.m.RequestContactAs(ctx, e.account, card, string(long), Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("1 KiB note cap not enforced: %v", err)
	}
	if err := e.m.RequestContactAs(ctx, e.account, card, "hi", Proof{Fingerprint: CardKey(card), SPKI: spki, Protocol: 1}); err != nil {
		t.Fatal(err)
	}
	evil, _, evilSPKI := guest(t, "Evil2")
	_, card2, _ := guest(t, "Someone")
	if err := e.m.RequestContactAs(ctx, e.account, card2, "", Proof{Fingerprint: evil.Fingerprint, SPKI: evilSPKI, Protocol: 1}); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("card/key mismatch accepted: %v", err)
	}
}

// UpdateContact is a card refresh now, not a key rotation. The chain that carried
// the call already decided the pin (PACT §5.3, §14.3), so the two things left to
// check are that the card names the pinned ROOT and carries the leaf the call
// proved. These replace four tests of the 1.x rotation proof, which required a
// signature by the old key because in 1.x the identity WAS a key.
func TestUpdateContactRefreshesTheCardAndNothingElse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	g, card, spki := guest(t, "Bharat")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: g.Fingerprint, SPKI: spki, Status: "active",
		Card: card, Protocol: 2, Leaf: g.Host.LeafDER, Endpoint: g.Host.Endpoint,
	}); err != nil {
		t.Fatal(err)
	}
	// The same root and the same leaf, a different display name: accepted.
	refreshed := g.Host.Card("Bharat Mehta", "required")
	if err := e.m.UpdateContact(ctx, e.account, g.Fingerprint, refreshed); err != nil {
		t.Fatalf("a card refresh from the pinned root was refused: %v", err)
	}
	if c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint); c.Card != refreshed {
		t.Error("the card was not replaced")
	}

	// A card from another root is not a refresh of this contact.
	other, otherCard, _ := guest(t, "Mallory")
	_ = other
	if err := e.m.UpdateContact(ctx, e.account, g.Fingerprint, otherCard); err == nil {
		t.Error("a card naming another root was accepted as a refresh")
	}
}
