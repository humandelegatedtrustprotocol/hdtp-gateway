package ownermcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// list_contacts gives a waiting request's address claim (HDTP §5.2), as the portal's Requests tab
// does: the owner's agent is told, beside a request, whose address it comes from. A request from an
// address nobody holds carries none.
func TestListContactsNamesWhoseAddressARequestComesFrom(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const at = "https://bharat.example/mcp"
	friend := testid.NewWallet(t, "Bharat")
	squatter := testid.NewWallet(t, "Bharat")
	stranger := testid.NewWallet(t, "Chen")
	for _, c := range []struct {
		w      *testid.Wallet
		at     string
		status string
	}{{friend, at, "active"}, {squatter, at, "pending_in"}, {stranger, "https://chen.example/mcp", "pending_in"}} {
		h := c.w.Issue(t, c.at)
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: c.w.Fpr, SPKI: h.Key.Public().SPKI,
			Status: c.status, Endpoint: c.at, Leaf: h.LeafDER, DisplayName: c.w.Fpr}); err != nil {
			t.Fatal(err)
		}
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "list_contacts", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatal(text)
	}
	var rows []struct {
		Fingerprint  string `json:"fingerprint"`
		Status       string `json:"status"`
		AddressClaim *struct {
			Root string `json:"root"`
		} `json:"address_claim"`
	}
	if err := json.Unmarshal([]byte(text), &rows); err != nil || len(rows) != 3 {
		t.Fatalf("list_contacts answered %s (%v)", text, err)
	}
	for _, r := range rows {
		want := ""
		if r.Fingerprint == squatter.Fpr {
			want = friend.Fpr
		}
		got := ""
		if r.AddressClaim != nil {
			got = r.AddressClaim.Root
		}
		if got != want {
			t.Errorf("%s (%s) carries address_claim %q, want %q", r.Fingerprint, r.Status, got, want)
		}
	}
}

// The name an address claim gives is the held contact's own name, stripped as it renders (HDTP §3):
// a bidi override in it does not reach the owner's agent.
func TestAnAddressClaimNamesTheHolderStripped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const at = "https://bharat.example/mcp"
	friend := testid.NewWallet(t, "Bharat")
	squatter := testid.NewWallet(t, "Bharat")
	for _, c := range []struct {
		w      *testid.Wallet
		status string
		name   string
	}{{friend, "active", "\u202eBharat\u0007"}, {squatter, "pending_in", "Bharat"}} {
		h := c.w.Issue(t, at)
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: c.w.Fpr, SPKI: h.Key.Public().SPKI,
			Status: c.status, Endpoint: at, Leaf: h.LeafDER, DisplayName: c.name}); err != nil {
			t.Fatal(err)
		}
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "list_contacts", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatal(text)
	}
	var rows []struct {
		Fingerprint  string `json:"fingerprint"`
		AddressClaim *struct {
			Root string `json:"root"`
			Name string `json:"name"`
		} `json:"address_claim"`
	}
	if err := json.Unmarshal([]byte(text), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Fingerprint == squatter.Fpr && (r.AddressClaim == nil || r.AddressClaim.Name != "Bharat") {
			t.Fatalf("the claim: %+v", r.AddressClaim)
		}
	}
}
