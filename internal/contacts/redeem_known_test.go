package contacts

import (
	"context"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// A root this account already holds a row for redeems one of its invites (review N-08, P-22).
//
// It used to spend a use and then fail the insert: every such caller was told `invite_invalid`
// with the use gone. For a blocked root that answer is an oracle — PACT §12: blocked MUST be
// indistinguishable from never-met, and a stranger holding the same link is let in — and for a
// root whose request is still waiting it threw away a one-time link that was meant for them.
func TestRedeemByARootThisAccountAlreadyHolds(t *testing.T) {
	ctx := context.Background()

	uses := func(t *testing.T, e *env, id string) int64 {
		t.Helper()
		list, err := e.st.ListInvites(ctx, e.account)
		if err != nil {
			t.Fatal(err)
		}
		for _, inv := range list {
			if inv.ID == id {
				return inv.Uses
			}
		}
		t.Fatalf("invite %s gone", id)
		return 0
	}
	hold := func(t *testing.T, e *env, g *guestID, card, status string) {
		t.Helper()
		if _, err := e.st.InsertContact(ctx, g.proof().pin(store.Contact{AccountID: e.account, Status: status, Card: card, PinnedAt: 1})); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a blocked root is answered as a stranger and nothing is spent or written", func(t *testing.T) {
		e := newEnv(t)
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
		g, card, _ := guest(t, "Blocked")
		hold(t, e, g, card, "blocked")
		res, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof())
		if err != nil || res.Status != "pending" {
			t.Fatalf("blocked root answered %+v, %v; a stranger is answered pending", res, err)
		}
		if n := uses(t, e, inv.ID); n != 0 {
			t.Errorf("a blocked root spent %d use(s) of a one-time invite", n)
		}
		if c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint); c.Status != "blocked" {
			t.Errorf("the blocked row became %s", c.Status)
		}
	})

	t.Run("a blocked root holding an auto-accept link is answered what a stranger would be", func(t *testing.T) {
		e := newEnv(t)
		token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true, Preset: "friend"})
		g, card, _ := guest(t, "Blocked")
		hold(t, e, g, card, "blocked")
		res, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof())
		if err != nil || res.Status != "accepted" || len(res.Permissions) == 0 {
			t.Fatalf("answered %+v, %v; a stranger is answered accepted with the invite's grant", res, err)
		}
		if c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint); c.Status != "blocked" || len(c.Permissions) != 0 {
			t.Errorf("the blocked row was written: %+v", c)
		}
	})

	t.Run("a spent or revoked link is still invite_invalid for a blocked root, as for a stranger", func(t *testing.T) {
		e := newEnv(t)
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		if err := e.st.RevokeInvite(ctx, e.account, inv.ID, e.clock.Unix()); err != nil {
			t.Fatal(err)
		}
		g, card, _ := guest(t, "Blocked")
		hold(t, e, g, card, "blocked")
		if _, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof()); err == nil {
			t.Fatal("a revoked link let a blocked root through; a stranger is refused")
		}
	})

	t.Run("a request still waiting redeems a link: promoted, one use", func(t *testing.T) {
		e := newEnv(t)
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true, Preset: "friend", MaxUses: 1})
		g, card, _ := guest(t, "Waiting")
		if err := e.m.RequestContactAs(ctx, e.account, card, "hello", g.proof()); err != nil {
			t.Fatal(err)
		}
		res, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof())
		if err != nil || res.Status != "accepted" {
			t.Fatalf("answered %+v, %v", res, err)
		}
		c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint)
		if c.Status != "active" || c.Preset != "friend" || c.InviteID != inv.ID || len(c.Permissions) == 0 {
			t.Fatalf("the waiting request was not promoted by the invite: %+v", c)
		}
		if n := uses(t, e, inv.ID); n != 1 {
			t.Errorf("spent %d uses, want 1", n)
		}
	})

	t.Run("a request still waiting redeems a manual link: still waiting, now through the invite", func(t *testing.T) {
		e := newEnv(t)
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{Label: "conference"})
		g, card, _ := guest(t, "Waiting")
		if err := e.m.RequestContactAs(ctx, e.account, card, "", g.proof()); err != nil {
			t.Fatal(err)
		}
		res, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof())
		if err != nil || res.Status != "pending" {
			t.Fatalf("answered %+v, %v", res, err)
		}
		if c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint); c.Status != "pending_in" || c.InviteID != inv.ID {
			t.Fatalf("row %+v; want pending_in carrying the invite (its label is the owner's context)", c)
		}
	})

	t.Run("a pinned contact reaching the guest tool is answered as a stranger, nothing written", func(t *testing.T) {
		e := newEnv(t)
		token, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{})
		g, card, _ := guest(t, "Demoted")
		hold(t, e, g, card, "active")
		res, err := e.m.RedeemAs(ctx, e.account, token, card, g.proof())
		if err != nil || res.Status != "pending" {
			t.Fatalf("answered %+v, %v", res, err)
		}
		if n := uses(t, e, inv.ID); n != 0 {
			t.Errorf("spent %d use(s)", n)
		}
		if c, _ := e.st.GetContact(ctx, e.account, g.Fingerprint); c.Status != "active" {
			t.Errorf("an active contact became %s through a guest redemption", c.Status)
		}
	})
}
