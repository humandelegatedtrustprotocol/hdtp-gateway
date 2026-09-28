package ownermcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// list_contacts gives a waiting request's address claim (PACT §5.2), as the portal's Requests tab
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
