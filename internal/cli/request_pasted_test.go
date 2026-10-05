package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The owner's add-by-card with a card pasted through a chat (HDTP §3, Reading a card; the owner's,
// 2026-10-05): it is asked, pinned pending_out under the card's name and address, and the card on
// file reads back with its seal.
func TestAPastedCardIsAsked(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "hdtp.db"))
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
	peer := testid.NewWallet(t, "Chitra")
	host := peer.Issue(t, "https://chitra.example/a/chitra/mcp")
	asked := 0
	ci := &contactInitiator{
		manager: &contacts.Manager{Store: st},
		audit:   func(string, string, string) {},
		request: func(context.Context, string, outbound.Peer, string, string) error { asked++; return nil },
	}
	res, err := ci.RequestContact(ctx, a.ID, testid.Pasted(t, host.Card("Chitra", "optional")), "")
	if err != nil || res.Status != "pending_out" || asked != 1 {
		t.Fatalf("a pasted card: %+v %v (asked %d)", res, err, asked)
	}
	c, err := st.GetContact(ctx, a.ID, peer.Fpr)
	if err != nil || c.Status != "pending_out" || c.DisplayName != "Chitra" || c.Endpoint != host.Endpoint {
		t.Fatalf("a pasted card must be pinned pending_out under its name and address: %+v %v", c, err)
	}
	if seal, err := contacts.SealOf(c.Card, time.Now()); err != nil || seal != "optional" {
		t.Fatalf("the pasted card on file reads its seal as %q: %v", seal, err)
	}
}
