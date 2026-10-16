package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// A pairing whose form names no account pairs the account accountMiddleware resolved for the
// request: the node's sole account when the signed-in owner administers it, none otherwise. The
// handler read the form alone and passed "", and Pair then paired the node's sole account whether or
// not the owner administered it.
func TestAPairingNamingNoAccountPairsTheOneTheOwnerAdministers(t *testing.T) {
	ctx := context.Background()
	var got []string
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountSettingsPages(mux, SettingsDeps{Owners: st, Effective: func() []core.Effective { return nil },
			Pair: func(_ context.Context, in PairInput) (PairResult, error) {
				got = append(got, in.Account)
				return PairResult{PublicName: "me.example", Adapter: "ingress-passthrough"}, nil
			},
			Unpair: func(context.Context, string) error { return nil },
		})
	})
	me, session := e.signIn(t, "Me")
	solo, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "solo", DisplayName: "Solo", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	pair := func() int {
		form := url.Values{"pair_url": {"https://ingress.example/pair"}, "token": {"t"}, "subdomain": {"me"}}
		req := httptest.NewRequest(http.MethodPost, "/settings/pair", strings.NewReader(form.Encode()))
		req.Host = "localhost:8080"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
		req.Header.Set("X-HDTP-Csrf", "tok")
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := pair(); code != http.StatusOK || len(got) != 1 || got[0] != "" {
		t.Errorf("an owner who administers no account: %d, Pair heard %q; want no account", code, got)
	}
	if err := e.st.AddMembership(ctx, me, solo.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if code := pair(); code != http.StatusOK || len(got) != 2 || got[1] != solo.ID {
		t.Errorf("an owner who administers the sole account: %d, Pair heard %q; want %s", code, got, solo.ID)
	}
}
