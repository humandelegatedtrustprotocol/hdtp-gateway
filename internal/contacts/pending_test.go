package contacts

// The manager's side of the pending-request cap (PACT §12's limits; `pending_in_cap` of the node's
// limits sidecar): every path a stranger writes a request by asks AdmitRequest, with the count of
// requests already held, before it writes; a refusal writes nothing and spends no use of an invite;
// a request already waiting is not asked about again; and a manager built without the cap writes no
// request at all. The decision itself is the sidecar's (internal/limits).

import (
	"context"
	"errors"
	"testing"
)

func TestTheRequestCapIsAskedBeforeEveryRequestIsWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var asked []int64
	full := false
	e.m.AdmitRequest = func(_ context.Context, accountID string, held int64) error {
		if accountID != e.account {
			t.Errorf("asked about %s, want the account the request is addressed to", accountID)
		}
		asked = append(asked, held)
		if full {
			return ErrRequestsFull
		}
		return nil
	}

	// The control: an admitted request is written, and was asked about with nothing held yet.
	first, card1, _ := guest(t, "First")
	if err := e.m.RequestContactAs(ctx, e.account, card1, "", first.proof()); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != 0 {
		t.Fatalf("asked with %v, want once with 0 held", asked)
	}
	// A redemption the owner must approve is a request too, and the count now holds the first.
	token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
	second, card2, _ := guest(t, "Second")
	if res, err := e.m.RedeemAs(ctx, e.account, token, card2, second.proof()); err != nil || res.Status != "pending" {
		t.Fatalf("an admitted redemption: %+v %v", res, err)
	}
	if len(asked) != 2 || asked[1] != 1 {
		t.Fatalf("asked with %v, want 1 held the second time", asked)
	}

	// At the cap: a request is refused and nothing is written.
	full = true
	third, card3, _ := guest(t, "Third")
	if err := e.m.RequestContactAs(ctx, e.account, card3, "", third.proof()); !errors.Is(err, ErrRequestsFull) {
		t.Fatalf("a request at the cap: %v, want ErrRequestsFull", err)
	}
	if _, err := e.st.GetContact(ctx, e.account, cardRoot(t, card3)); err == nil {
		t.Fatal("a refused request was written")
	}
	// A redemption at the cap is refused before the use is spent: the link still works later.
	token2, inv, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
	if _, err := e.m.RedeemAs(ctx, e.account, token2, card3, third.proof()); !errors.Is(err, ErrRequestsFull) {
		t.Fatalf("a redemption at the cap: %v, want ErrRequestsFull", err)
	}
	if got, _ := e.st.GetInviteByHash(ctx, e.account, inv.TokenHash); got.Uses != 0 {
		t.Fatalf("a refused redemption spent a use of the invite: %d", got.Uses)
	}
	// A request already waiting re-redeems a link without being counted again.
	n := len(asked)
	token3, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{MaxUses: 1})
	if _, err := e.m.RedeemAs(ctx, e.account, token3, card1, first.proof()); err != nil {
		t.Fatalf("a waiting request redeeming a link at the cap: %v", err)
	}
	if len(asked) != n {
		t.Fatalf("a waiting request was asked about again: %v", asked)
	}
	// An auto-accept link adds a contact, not a request: the contact cap's to decide, not this.
	token4, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true})
	fourth, card4, _ := guest(t, "Fourth")
	if res, err := e.m.RedeemAs(ctx, e.account, token4, card4, fourth.proof()); err != nil || res.Status != "accepted" {
		t.Fatalf("an auto-accept redemption at the request cap: %+v %v", res, err)
	}
	if len(asked) != n {
		t.Fatalf("an auto-accept redemption was asked about: %v", asked)
	}
}

func TestAManagerWithoutTheCapWritesNoRequest(t *testing.T) {
	e := newEnv(t)
	e.m.AdmitRequest = nil
	ctx := context.Background()
	g, card, _ := guest(t, "G")
	if err := e.m.RequestContactAs(ctx, e.account, card, "", g.proof()); !errors.Is(err, ErrRequestsFull) {
		t.Fatalf("a request with no cap wired: %v, want refused", err)
	}
	if _, err := e.st.GetContact(ctx, e.account, cardRoot(t, card)); err == nil {
		t.Fatal("a request was written with no cap wired")
	}
}
