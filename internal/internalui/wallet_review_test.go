package internalui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// The review of 2026-09-28 on the web wallet's pages.

func walletReviewEnv(t *testing.T, mint func(*http.Request, store.Account, string, string, string) (identity.CSRResult, error)) (*http.ServeMux, store.Account) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	if err := st.SetAccountRoot(ctx, a.ID, "sha256:root", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateOwnerWithID(ctx, "owner-a", "Owner A"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, "owner-a", a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountWalletPages(mux, WalletDeps{
		Store: st, WalletOrigin: "https://wallet.example",
		Endpoint: func(slug string) string { return "https://node.example/a/" + slug + "/mcp" },
		Purpose:  func(*http.Request, string, string) (string, error) { return identity.PurposeRenew, nil },
		Mint:     mint,
		Audit:    func(string, string, string) {},
		Now:      time.Now,
	})
	return mux, a
}

// L8. A request the node failed to make is answered with a fixed sentence: the page never carries
// the error's text, which can name a database, a path or a key id. A refusal says what was refused.
func TestTheWalletStartPageCarriesNoErrorText(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		status int
	}{
		{"failure", errors.New("pq: connection to 10.0.0.7 refused SECRET-DETAIL"), http.StatusInternalServerError},
		{"vacated", errors.Join(errors.New("SECRET-DETAIL"), store.ErrAddressVacated), http.StatusConflict},
	} {
		t.Run(c.name, func(t *testing.T) {
			mux, _ := walletReviewEnv(t, func(*http.Request, store.Account, string, string, string) (identity.CSRResult, error) {
				return identity.CSRResult{}, c.err
			})
			req := httptest.NewRequest("POST", "https://portal.example/identity/alina/wallet/start", strings.NewReader(url.Values{}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(context.WithValue(req.Context(), ownerKey{}, "owner-a"))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != c.status || strings.Contains(rr.Body.String(), "SECRET-DETAIL") {
				t.Fatalf("status %d, body %q", rr.Code, rr.Body.String())
			}
		})
	}
}

// Coordinator item 7. The portal's own origin is the redirect a wallet answers to, and a wallet
// answers http only at a loopback host in the core's normal form: localhost, a dotted quad in
// 127.0.0.0/8, or [::1]. The portal accepted anything net.ParseIP calls loopback, [::ffff:7f00:1]
// among them, and minted a request the wallet then refused. The two rules are held to each other
// here: for each host, the portal's answer is the core's (hdtpidentity.SigningRequestCheck on a
// request redirecting there).
func TestThePortalsLoopbackRuleIsTheWallets(t *testing.T) {
	for _, host := range []string{
		"localhost:8080", "127.0.0.1:8080", "127.9.8.7", "[::1]:8080",
		"[::ffff:7f00:1]:8080", "[::ffff:127.0.0.1]:8080", "[0:0:0:0:0:0:0:1]:8080", "127.000.0.1:8080", "0x7f.0.0.1",
		"10.0.0.7:8080", "portal.example", "localhost.:8080",
	} {
		r := httptest.NewRequest("GET", "http://"+host+"/identity/alina/wallet", nil)
		_, portalErr := walletPortalOrigin(r)
		origin := "http://" + host
		_, coreErr := hdtpidentity.SigningRequestCheck(map[string]any{
			"csr": "x", "purpose": "renew", "expect_root": "x", "redirect": origin + "/wallet/return?slug=alina", "state": "x",
			"recipient": "x", "valid_days": "1", "expires": "x",
		}, origin, time.Now(), nil)
		walletRefuses := coreErr != nil && (strings.Contains(coreErr.Error(), "redirect") || strings.Contains(coreErr.Error(), "origin"))
		if (portalErr != nil) != walletRefuses {
			t.Errorf("%s: the portal says %v, the wallet %v", host, portalErr, coreErr)
		}
	}
}

// Coordinator (QA of 2026-09-28), item 3. A signed-out GET of the wallet page answered a bare 404,
// so the link the import and the move notice give led nowhere. It sends the person to sign in,
// with the page to come back to; the sign-in view returns there (web/src/views/login.tsx) only for
// a path on this portal.
func TestASignedOutWalletPageSendsThePersonToSignIn(t *testing.T) {
	mux, _ := walletReviewEnv(t, nil)
	req := httptest.NewRequest("GET", "https://portal.example/identity/alina/wallet", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/login?next=%2Fidentity%2Falina%2Fwallet" {
		t.Fatalf("signed out: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	// Signed in as somebody who does not administer it: still not found, as before.
	req = httptest.NewRequest("GET", "https://portal.example/identity/alina/wallet", nil)
	req = req.WithContext(context.WithValue(req.Context(), ownerKey{}, "someone-else"))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("another owner: %d", rr.Code)
	}
}
