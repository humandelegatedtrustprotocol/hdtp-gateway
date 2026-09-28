package cli

// The owner's own ways to add a contact — redeeming somebody's invite link, and asking the holder
// of a card — are held to the contact cap (limit.contacts) BEFORE anything leaves the node: the row
// either writes (active or pending_out) counts, and one the peer accepted is never refused
// afterwards, which would leave them holding a contact we do not.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

func TestTheOwnersAddsAreHeldToTheCapBeforeAnythingLeaves(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:the-one", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	p := newTestPeer(t, "Chitra", "https://chitra.example/mcp")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(offerFor(t, p, "Chitra"))
	}))
	t.Cleanup(srv.Close)
	ours := testid.CardFor(t, "Alina", "https://alina.example/mcp")

	var rows []string
	left := 0
	ci := &contactInitiator{
		manager:    &contacts.Manager{Store: st, ContactCap: func() int { return 1 }},
		card:       func(context.Context, string) (string, error) { return ours, nil },
		outbound:   func(string) (*outbound.Client, error) { left++; return nil, errors.New("dialled") },
		request:    func(context.Context, string, outbound.Peer, string, string) error { left++; return nil },
		audit:      func(action, resource, outcome string) { rows = append(rows, action+" → "+outcome) },
		httpClient: srv.Client,
	}
	if _, err := ci.RedeemInvite(ctx, a.ID, srv.URL+"/i/tok", ""); !errors.Is(err, contacts.ErrContactCap) {
		t.Fatalf("redeeming a link at the cap: %v", err)
	}
	card := testid.CardFor(t, "Dev", "https://dev.example/mcp")
	if _, err := ci.RequestContact(ctx, a.ID, card, ""); !errors.Is(err, contacts.ErrContactCap) {
		t.Fatalf("sending a request at the cap: %v", err)
	}
	if left != 0 {
		t.Fatalf("%d calls left the node for adds the cap refused", left)
	}
	if len(rows) != 2 || rows[0] != "contact_initiate → contact_cap" || rows[1] != "contact_initiate → contact_cap" {
		t.Fatalf("audit %q", rows)
	}
	// Room for one: the request goes.
	ci.manager.ContactCap = func() int { return 2 }
	if _, err := ci.RequestContact(ctx, a.ID, card, ""); err != nil || left != 1 {
		t.Fatalf("a request with room: %v (sent %d)", err, left)
	}
}
