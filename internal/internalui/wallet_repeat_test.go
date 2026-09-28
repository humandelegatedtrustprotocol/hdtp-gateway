package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// An install that repeats its `state` or `chain` is judged by the first value of each, and the
// service sees exactly one of each: a form cannot hand the check one state and the install
// another. (The state must then be the pending request's, once — internal/identity
// TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState.)
func TestARepeatedWalletFieldReachesTheInstallOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	o, err := e.st.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, o.ID, a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	var states []string
	var chains [][][]byte
	d := WalletDeps{Store: e.st, Install: func(_ *http.Request, _ store.Account, chain [][]byte, state string) (WalletInstalled, error) {
		states, chains = append(states, state), append(chains, chain)
		return WalletInstalled{}, nil
	}}
	mux := http.NewServeMux()
	MountWalletPages(mux, d)
	form := url.Values{"state": {"first-state", "second-state"}, "chain": {"AQ.Ag", "Aw.BA"}}
	r := httptest.NewRequest(http.MethodPost, "/identity/alice/wallet/install", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), ownerKey{}, o.ID))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("the install answered %d %s", rec.Code, rec.Body)
	}
	if len(states) != 1 || states[0] != "first-state" {
		t.Fatalf("the install saw states %q, want the first one alone", states)
	}
	if len(chains) != 1 || len(chains[0]) != 2 || chains[0][0][0] != 1 || chains[0][1][0] != 2 {
		t.Fatalf("the install saw chains %v, want the first one alone", chains)
	}
}
