package contacts

import (
	"context"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// PACT §5.2: "A stranger whose leaf names an endpoint the receiver has pinned for another root,
// or had pinned for another root within the last 30 days, is never auto-accepted — an invite's
// auto_accept does not apply." The node's core computed the claim for a sealed guest and nothing
// read it: the cloud's conformance battery, aimed at a node (harness S19), had a new root at the
// paired peer's address redeem an auto-accept invite, and the node admitted it as a contact.
func TestAStrangerAtAPinnedContactsAddressIsNeverAutoAccepted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	link := func() string {
		token, _, err := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true, Preset: "friend"})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	bharat, card, _ := guest(t, "Bharat")
	if res, err := e.m.RedeemAs(ctx, e.account, link(), card, bharat.proof()); err != nil || res.Status != "accepted" {
		t.Fatalf("the control: bharat's own redemption answered %+v %v", res, err)
	}

	// Mallory: a new root whose leaf names Bharat's address.
	w := testid.NewWallet(t, "Mallory")
	h := w.Issue(t, bharat.Host.Endpoint)
	mallory := &guestID{Fingerprint: w.Fpr, Host: h}
	p := mallory.proof()
	claim, err := e.m.AddressClaim(ctx, e.account, p.Endpoint, p.Fingerprint)
	if err != nil || claim != bharat.Fingerprint {
		t.Fatalf("the claim on bharat's address is %q (%v), want bharat's root", claim, err)
	}
	p.AddressClaim = claim
	res, err := e.m.RedeemAs(ctx, e.account, link(), h.Card("Bharat", ""), p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending" {
		t.Fatalf("a stranger at a contact's address redeemed an auto-accept invite and was answered %q", res.Status)
	}
	if c, err := e.st.GetContact(ctx, e.account, w.Fpr); err != nil || c.Status != "pending_in" {
		t.Fatalf("the stranger's row is %+v (%v), want pending_in for the owner to decide", c, err)
	}
}

// The store-side claim, for a guest proven by its client certificate, applies the rule the core
// applies to a sealed guest (pact-identity envelope.go, Decide's address_claim): a current pin of
// another root at the endpoint, else a former endpoint of another root younger than ClaimWindow.
func TestAddressClaimFollowsTheCoresRule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bharat, card, _ := guest(t, "Bharat")
	token, _, _ := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true})
	if _, err := e.m.RedeemAs(ctx, e.account, token, card, bharat.proof()); err != nil {
		t.Fatal(err)
	}
	const moved = "https://old.example/mcp"
	within := e.clock.Add(-pactidentity.ClaimWindow + time.Hour).Unix()
	past := e.clock.Add(-pactidentity.ClaimWindow - time.Hour).Unix()
	// Real roots, as every writer of a former endpoint has one: the same rows are what the core's
	// Decide reads for a sealed guest, and it holds a root to being a fingerprint.
	recent, longAgo, stranger := testid.NewWallet(t, "Recent").Fpr, testid.NewWallet(t, "Long Ago").Fpr, testid.NewWallet(t, "Stranger").Fpr
	if err := e.st.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: e.account, Root: recent, Endpoint: moved, At: within}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: e.account, Root: longAgo, Endpoint: "https://ancient.example/mcp", At: past}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, endpoint, root, want string
	}{
		{"another root pinned there", bharat.Host.Endpoint, stranger, bharat.Fingerprint},
		{"the pinned root itself", bharat.Host.Endpoint, bharat.Fingerprint, ""},
		{"a former address inside the window", moved, stranger, recent},
		{"the root that moved away, at its former address", moved, recent, ""},
		{"a former address past the window", "https://ancient.example/mcp", stranger, ""},
		{"an address nobody held", "https://fresh.example/mcp", stranger, ""},
	} {
		got, err := e.m.AddressClaim(ctx, e.account, c.endpoint, c.root)
		if err != nil || got != c.want {
			t.Errorf("%s: claim %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}
