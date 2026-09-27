package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// The portal's pages are account-scoped, and every one of them read the account
// from `?account=`. The dashboard's own navigation carried no such parameter, so
// following a link from the dashboard reached a page with an EMPTY account:
// `/card` answered 404, `POST /invites/create?account=` answered 400, and the
// list pages rendered blank because a query for account "" matches nothing.
//
// The whole portal was therefore unusable by clicking. It went unnoticed because
// the live portal scenario BUILDS its URLs — `"/card?account=" + p.AccountID` —
// rather than following the links a person would, so it proved the pages render
// and never that they can be reached.
//
// The account is resolved server-side now and does not appear in the URL at all.
func TestPagesResolveTheAccountWithoutItBeingInTheURL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.InsertCredential(ctx, store.Credential{
		OwnerID: mustOwner(t, e.st), Kind: "passkey", Tag: "phone", Data: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}

	h := accountMiddleware(e.st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What a page handler sees. It must be the real account, from a URL that
		// never mentioned one.
		_, _ = w.Write([]byte(r.URL.Query().Get("account")))
	}), nil)

	owner := ownerOf(t, e.st)
	for _, path := range []string{"/card", "/invites", "/contacts", "/invites/create"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "127.0.0.1:5555"
		h.ServeHTTP(rr, signedIn(req, owner))
		if got := rr.Body.String(); got != acct.ID {
			t.Errorf("%s: handler saw account %q, want %q — the page cannot know which "+
				"identity it is for", path, got, acct.ID)
		}
	}

	// An explicitly EMPTY parameter is the same as none: that is exactly what the
	// dashboard's forms were producing (`?account=`).
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/invites/create?account=", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	h.ServeHTTP(rr, signedIn(req, owner))
	if rr.Body.String() != acct.ID {
		t.Errorf("an empty ?account= was not resolved: %q", rr.Body.String())
	}
}

// A request that NAMES an account must keep it: resolution fills a gap, it never
// overrides a choice.
func TestAnExplicitAccountIsNeverOverridden(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	chosen, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "one", DisplayName: "One", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "two", DisplayName: "Two", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	owner := ownerOf(t, e.st)
	h := accountMiddleware(e.st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("account")))
	}), nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/card?account="+chosen.ID, nil)
	h.ServeHTTP(rr, signedIn(req, owner))
	if rr.Body.String() != chosen.ID {
		t.Errorf("an explicit account was overridden: %q", rr.Body.String())
	}
	_ = other
}

// With SEVERAL identities there is no single right answer, and guessing would
// show one person's inbox under another's name. Nothing is filled in.
func TestSeveralAccountsAreNeverGuessedBetween(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, s := range []string{"alice", "bob"} {
		if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
			Slug: s, DisplayName: s, Algo: "p256"}); err != nil {
			t.Fatal(err)
		}
	}
	h := accountMiddleware(e.st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[" + r.URL.Query().Get("account") + "]"))
	}), nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/card", nil)
	h.ServeHTTP(rr, req)
	if got := rr.Body.String(); got != "[]" {
		t.Errorf("with two identities the portal picked %s on its own", got)
	}
}

// And the whole point: the dashboard's links must be followable. This drives the
// real mux, not the middleware in isolation.
func TestDashboardLinksAreReachable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.InsertCredential(ctx, store.Credential{
		OwnerID: mustOwner(t, e.st), Kind: "passkey", Tag: "phone", Data: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"}); err != nil {
		t.Fatal(err)
	}
	h := HandlerWithAuth(e.st, NewSetupTokens(), nil,
		func(mux *http.ServeMux) { MountDashboard(mux, DashboardDeps{Store: e.st, Setup: NewSetupTokens()}) },
		func(mux *http.ServeMux) { MountManagePages(mux, ManageDeps{Store: e.st}) },
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("dashboard: %d", rr.Code)
	}
	// Follow the links whose pages this test mounts. The full sweep — every link
	// on a real node, with every page mounted — is the live portal scenario;
	// here the point is that a mounted, account-scoped page is REACHABLE from the
	// dashboard without the URL naming an account.
	mounted := map[string]bool{"/card": true, "/invites": true, "/requests": true}
	for _, href := range hrefsIn(body) {
		if !mounted[href] {
			continue
		}
		lr := httptest.NewRecorder()
		lq := httptest.NewRequest("GET", href, nil)
		lq.RemoteAddr = "127.0.0.1:5555"
		h.ServeHTTP(lr, lq)
		if lr.Code == http.StatusNotFound {
			t.Errorf("the dashboard links to %s and it answers 404", href)
		}
	}
}

func hrefsIn(body string) []string {
	var out []string
	for _, part := range strings.Split(body, `href="`)[1:] {
		if i := strings.IndexByte(part, '"'); i > 0 {
			out = append(out, part[:i])
		}
	}
	return out
}

// signedIn returns the request a real one is: carrying an owner session. Account
// resolution only runs for one (§8.3 requires a session on every bind), so a
// test that drives accountMiddleware without an owner is testing the sign-in
// page, not the portal.
func signedIn(req *http.Request, owner string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ownerKey{}, owner))
}

// ownerOf registers an owner who administers every existing account.
func ownerOf(t *testing.T, st *store.SQLite) string {
	t.Helper()
	ctx := context.Background()
	id := mustOwner(t, st)
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accts {
		if err := st.AddMembership(ctx, id, a.ID, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	return id
}
