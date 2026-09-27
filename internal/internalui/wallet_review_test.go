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

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
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
