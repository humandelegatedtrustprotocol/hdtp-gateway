package internalui

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/testid"
)

func landingEnv(t *testing.T) (http.Handler, *contacts.Manager, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Sumit", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	cm := &contacts.Manager{Store: st}
	mux := http.NewServeMux()
	mux.Handle("/i/{token}", LandingHandler(LandingDeps{
		Store: st,
		SignCard: func(accountID string) (string, string, error) {
			return testid.CardFor(t, "Sumit", "https://pact.example/mcp"), "c2ln", nil
		},
		PublicURL: func() string { return "https://pact.example" },
	}))
	_ = a
	return mux, cm, a.ID
}

func TestLandingRendersSignedCardAndQR(t *testing.T) {
	h, cm, acct := landingEnv(t)
	token, _, err := cm.CreateInvite(context.Background(), acct, contacts.InviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/i/"+token, nil))
	if rr.Code != 200 {
		t.Fatalf("landing: %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Sumit", "X-PACT-CERT:", "data:image/png;base64,", "signature"} {
		if !strings.Contains(body, want) {
			t.Fatalf("landing missing %q", want)
		}
	}
	for _, bad := range []string{`src="http`, `href="http`} {
		if strings.Contains(body, bad) {
			t.Fatalf("external asset reference: %s", bad)
		}
	}
}

func TestLandingNoOracle404(t *testing.T) {
	h, cm, acct := landingEnv(t)
	ctx := context.Background()

	// three invalid states + pure garbage must be byte-identical 404s
	revoked, inv, _ := cm.CreateInvite(ctx, acct, contacts.InviteOptions{})
	st := cm.Store
	if err := st.RevokeInvite(ctx, inv.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	expired, inv2, _ := cm.CreateInvite(ctx, acct, contacts.InviteOptions{TTL: time.Nanosecond})
	_ = inv2

	bodies := map[string]string{}
	for name, tok := range map[string]string{
		"unknown": "deadbeefdeadbeef", "revoked": revoked, "expired": expired,
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/i/"+tok, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", name, rr.Code)
		}
		bodies[name] = rr.Body.String()
	}
	if bodies["unknown"] != bodies["revoked"] || bodies["revoked"] != bodies["expired"] {
		t.Fatal("404 bodies differ — invite-state oracle")
	}
	_ = sha256.Sum256
}

// AC (P8-01): the invite link is built from the node's LIVE public URL. It is
// only ever encoded into the QR, so the pin is that the rendered page changes
// when the public URL does — a captured value would keep printing the old host
// while the card advertises the new one.
func TestLandingLinkFollowsALivePublicURL(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Sumit", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	cm := &contacts.Manager{Store: st}
	token, _, err := cm.CreateInvite(ctx, a.ID, contacts.InviteOptions{MaxUses: 1, Preset: "friend"})
	if err != nil {
		t.Fatal(err)
	}

	base := "https://first.example"
	h := LandingHandler(LandingDeps{
		Store: st,
		SignCard: func(string) (string, string, error) {
			return "BEGIN:VCARD\r\nVERSION:4.0\r\nEND:VCARD\r\n", "sig", nil
		},
		PublicURL: func() string { return base },
	})
	render := func() string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/i/"+token, nil)
		req.SetPathValue("token", token)
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("landing: %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	first := render()
	base = "https://moved.example"
	if second := render(); first == second {
		t.Fatal("the invite QR did not change when the public URL did: " +
			"the link is built from a snapshot, so it would keep naming the old host")
	}
}
