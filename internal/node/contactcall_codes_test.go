package node

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// A call to a contact the account does not hold is store.ErrNotFound, and to a row in any other
// state than active contacts.ErrWrongState, before anything is dialled: the owner MCP's call_contact
// answers them not_found and conflict (ownermcp.callFailureCode). The control, an active row, gets
// past the contact and fails on the account this bare node does not serve.
func TestCallingAContactNamesWhyItCannotBeCalled(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "call.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	for fpr, status := range map[string]string{"sha256:asked": "pending_out", "sha256:blocked": "blocked", "sha256:on": "active"} {
		if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct.ID, Fingerprint: fpr, Status: status, Endpoint: "https://p.example/mcp", Leaf: []byte{1}}); err != nil {
			t.Fatal(err)
		}
	}
	n := &Node{opts: Options{Store: st}}

	if _, err := n.CallContact(ctx, acct.ID, "sha256:nobody", "get_card", nil); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a contact the account does not hold: %v, want store.ErrNotFound", err)
	}
	for _, fpr := range []string{"sha256:asked", "sha256:blocked"} {
		_, err := n.CallContact(ctx, acct.ID, fpr, "get_card", nil)
		if !errors.Is(err, contacts.ErrWrongState) || errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: %v, want contacts.ErrWrongState", fpr, err)
		}
	}
	_, err = n.CallContact(ctx, acct.ID, "sha256:on", "get_card", nil)
	if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, contacts.ErrWrongState) {
		t.Errorf("an active contact must get past the contact check: %v", err)
	}
}
