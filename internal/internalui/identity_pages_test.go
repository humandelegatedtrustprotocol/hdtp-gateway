package internalui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// Settings · identity, as it is once key rotation is gone.
//
// This file tested rotation: typing the slug to confirm, the grace period, an
// incomplete fan-out reported rather than rounded up. PACT 2.0 does not rotate a
// key — a root is never rotated and a renewal is a new leaf a contact learns from
// the chain — so the route and its confirmation ceremony went, and what is left to
// test is what the page still does: list the identities, and create one.

func identityHarness(t *testing.T, create func(context.Context, string, string, string) (store.Account, error)) (*http.ServeMux, *[]string) {
	t.Helper()
	var audits []string
	mux := http.NewServeMux()
	MountIdentityPages(mux, IdentityDeps{
		Accounts: func(context.Context) ([]store.Account, error) {
			return []store.Account{{ID: "acct-1", Slug: "alice", DisplayName: "Alice", Algo: "p256", Fingerprint: "sha256:aaa"}}, nil
		},
		Create: create,
		Audit:  func(a, r, o string) { audits = append(audits, a+"/"+o) },
	})
	return mux, &audits
}

func createPost(mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/identity/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestIdentityListingAnswersTheAccounts(t *testing.T) {
	mux, _ := identityHarness(t, nil)
	req := httptest.NewRequest("GET", "/api/identity", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/identity = %d", w.Code)
	}
	var out struct {
		Rows []struct {
			Slug, DisplayName, Fingerprint string
		}
		CanCreate bool `json:"can_create"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("body: %s", w.Body.String())
	}
	if len(out.Rows) != 1 || out.Rows[0].Slug != "alice" || out.Rows[0].Fingerprint != "sha256:aaa" {
		t.Fatalf("rows = %+v", out.Rows)
	}
	// Create is nil here, and the affordance must be hidden rather than offered as
	// a button that cannot work.
	if out.CanCreate {
		t.Error("can_create is true with no Create dep")
	}
}

func TestCreatingAnIdentityNeedsBothFields(t *testing.T) {
	called := 0
	mux, audits := identityHarness(t, func(context.Context, string, string, string) (store.Account, error) {
		called++
		return store.Account{ID: "acct-2", Slug: "bob", DisplayName: "Bob"}, nil
	})
	for _, form := range []url.Values{
		{"slug": {"bob"}},
		{"name": {"Bob"}},
		{},
	} {
		if w := createPost(mux, form); w.Code != 200 {
			t.Fatalf("%v = %d", form, w.Code)
		}
	}
	if called != 0 {
		t.Errorf("an incomplete form reached Create %d times", called)
	}
	if len(*audits) != 0 {
		t.Errorf("an incomplete form was audited: %v", *audits)
	}
}

func TestCreatingAnIdentitySucceedsAndIsAudited(t *testing.T) {
	mux, audits := identityHarness(t, func(_ context.Context, slug, name, algo string) (store.Account, error) {
		if slug != "bob" || name != "Bob" || algo != "ed25519" {
			t.Errorf("Create got %q %q %q", slug, name, algo)
		}
		return store.Account{ID: "acct-2", Slug: slug, DisplayName: name}, nil
	})
	w := createPost(mux, url.Values{"slug": {"bob"}, "name": {"Bob"}, "algo": {"ed25519"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Created Bob") {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if len(*audits) != 1 || (*audits)[0] != "account_create/ok" {
		t.Errorf("audits = %v", *audits)
	}
}

func TestAFailedCreateIsReportedAndAudited(t *testing.T) {
	mux, audits := identityHarness(t, func(context.Context, string, string, string) (store.Account, error) {
		return store.Account{}, errors.New("slug already taken")
	})
	w := createPost(mux, url.Values{"slug": {"alice"}, "name": {"Alice"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "slug already taken") {
		t.Fatalf("failed create: %d %s", w.Code, w.Body.String())
	}
	if len(*audits) != 1 || (*audits)[0] != "account_create/error" {
		t.Errorf("audits = %v", *audits)
	}
}
