package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// The owner's add-by-card with a card whose certificate a copy cut: refused with what the person can
// do about it — send the card's file or its invite link, which a paste cannot damage — and nothing
// is asked. The same card whole is asked (the control).
func TestACutCardSaysWhatToDo(t *testing.T) {
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
	card := host.Card("Chitra", "optional")

	asked := 0
	ci := &contactInitiator{
		manager: &contacts.Manager{Store: st},
		audit:   func(string, string, string) {},
		request: func(context.Context, string, outbound.Peer, string, string) error { asked++; return nil },
	}
	cut := testid.WithCert(t, card, hdtpidentity.B64url(host.LeafDER)[:120])
	_, err = ci.RequestContact(ctx, a.ID, cut, "")
	if err == nil || !strings.Contains(err.Error(), "send the card's file (.vcf) or its invite link") {
		t.Fatalf("a cut certificate must be refused with what to do: %v", err)
	}
	if asked != 0 {
		t.Fatal("a card that did not read was asked")
	}
	// Another refusal does not carry the hint: it is not something a file or a link would fix.
	for _, tc := range []struct{ what, text string }{
		{"a card of another version", strings.Replace(card, "X-HDTP-VERSION:1", "X-HDTP-VERSION:2", 1)},
		{"a card with no certificate", testid.WithoutCert(t, card)},
	} {
		_, err = ci.RequestContact(ctx, a.ID, tc.text, "")
		if err == nil || strings.Contains(err.Error(), "invite link") {
			t.Fatalf("%s: %v", tc.what, err)
		}
	}

	res, err := ci.RequestContact(ctx, a.ID, card, "")
	if err != nil || res.Status != "pending_out" || asked != 1 {
		t.Fatalf("the card whole: %+v %v (asked %d)", res, err, asked)
	}
}
