package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// SPEC §3.3 makes owner→account a membership, and the owner MCP enforces it on
// every tool through policy.AllowOwnerManage. The portal enforced nothing: it
// read `account` from the query string or the form body and passed it to the
// store. The only thing between a signed-in owner and another owner's inbox,
// contacts and card was that v1's registration happens to produce exactly one
// owner — a property of passkeys.go, not an access-control decision.
func TestPortalRefusesAnAccountTheOwnerDoesNotAdminister(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	mine, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	me, err := e.st.CreateOwnerWithID(ctx, "", "Me")
	if err != nil {
		t.Fatal(err)
	}
	them, err := e.st.CreateOwnerWithID(ctx, "", "Them")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, me.ID, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, them.ID, theirs.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	// Exercised against the middleware itself with a probe behind it: newEnv
	// mounts no page routes, so asserting on a page's status code would measure
	// whether the route exists rather than whether the guard runs.
	reached := func(owner, account string) bool {
		var got bool
		h := accountMiddleware(e.st, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			got = true
		}), nil)
		r := httptest.NewRequest(http.MethodGet, "/contacts?account="+account, nil)
		if owner != "" {
			r = r.WithContext(context.WithValue(r.Context(), ownerKey{}, owner))
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}

	if !reached(me.ID, mine.ID) {
		t.Error("an owner was refused their OWN account")
	}
	if reached(me.ID, theirs.ID) {
		t.Errorf("owner %s reached account %s, which belongs to another owner",
			me.ID, theirs.ID)
	}
	// The sole-account fallback must be scoped too, or naming nothing becomes the
	// way around naming something.
	var viaFallback bool
	h := accountMiddleware(e.st, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		viaFallback = r.URL.Query().Get("account") == theirs.ID
	}), nil)
	r := httptest.NewRequest(http.MethodGet, "/contacts", nil)
	r = r.WithContext(context.WithValue(r.Context(), ownerKey{}, me.ID))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if viaFallback {
		t.Error("the sole-account fallback handed an owner an account they do not administer")
	}
}

// A request with no session must resolve NO account — and must not be refused
// for it. Both halves matter, and the second is a bug this test exists to keep
// out: account resolution runs inside the session gate, so the only requests
// reaching it owner-less are the ones §8.3 leaves open — above all the sign-in
// view. When resolution first started scoping by membership it 404'd those on
// any node with exactly one account, which locked the owner out of the page
// they sign in on.
func TestNoSessionResolvesNoAccountAndIsNotRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "solo", DisplayName: "Solo", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}

	var seen string
	served := false
	h := accountMiddleware(e.st, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		served = true
		seen = r.URL.Query().Get("account")
	}), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !served || rec.Code == http.StatusNotFound {
		t.Fatalf("a session-less request was refused (%d) — this is the sign-in page", rec.Code)
	}
	if seen != "" {
		t.Errorf("a session-less request resolved account %q; it is entitled to none", seen)
	}
	_ = a
}
