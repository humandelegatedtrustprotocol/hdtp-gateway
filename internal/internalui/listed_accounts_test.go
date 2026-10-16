package internalui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

func (c *canaryStore) ListAccounts(ctx context.Context) ([]store.Account, error) {
	if err := c.err("ListAccounts"); err != nil {
		return nil, err
	}
	return c.Store.ListAccounts(ctx)
}

// The Identity page, the Settings page's pairing selector and storage rows, and the owners page's
// token scopes list the accounts the signed-in owner administers, as the switcher does: they listed
// every account on the node, so an account with no membership showed there, and every action on it
// then answered 404. A list that could not be read is 500, never an empty one: Settings and owners
// dropped the error.
func TestTheAccountListsAreTheOwnersAccounts(t *testing.T) {
	ctx := context.Background()
	fail, failStorage := false, false
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		cs := &canaryStore{Store: st, fail: map[string]bool{}}
		listed := func(ctx context.Context) ([]store.Account, error) {
			cs.fail["ListAccounts"] = fail
			return cs.ListAccounts(ctx)
		}
		MountIdentityPages(mux, IdentityDeps{Accounts: listed, Owners: st})
		MountSettingsPages(mux, SettingsDeps{Owners: st, Effective: func() []core.Effective { return nil },
			Accounts: func(ctx context.Context) ([]AccountChoice, error) {
				accts, err := listed(ctx)
				out := make([]AccountChoice, 0, len(accts))
				for _, a := range accts {
					out = append(out, AccountChoice{ID: a.ID, Label: a.Slug})
				}
				return out, err
			},
			Storage: func(ctx context.Context) ([]StorageRow, error) {
				if failStorage {
					return nil, errors.New(pageCanary)
				}
				accts, err := st.ListAccounts(ctx)
				out := make([]StorageRow, 0, len(accts))
				for _, a := range accts {
					out = append(out, StorageRow{AccountID: a.ID, Label: a.Slug})
				}
				return out, err
			},
		})
		MountOwnerPages(mux, OwnersDeps{Store: &ownersStore{canaryStore: cs, fail: &fail}, Tokens: &auth.TokenService{Store: st}})
	})
	me, session := e.signIn(t, "Me")
	mine, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/identity", "/api/settings", "/api/owners"} {
		fail = false
		rec := e.do(t, http.MethodGet, path, nil, []*http.Cookie{session})
		if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, mine.ID) || strings.Contains(body, "theirs") {
			t.Errorf("GET %s: %d %s; want mine and not theirs", path, rec.Code, body)
		}
		fail = true
		if rec := e.do(t, http.MethodGet, path, nil, []*http.Cookie{session}); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), pageCanary) {
			t.Errorf("GET %s with the account list failing: %d %s; want 500", path, rec.Code, rec.Body.String())
		}
	}
	fail, failStorage = false, true
	if rec := e.do(t, http.MethodGet, "/api/settings", nil, []*http.Cookie{session}); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), pageCanary) {
		t.Errorf("GET /api/settings with the storage rows failing: %d %s; want 500", rec.Code, rec.Body.String())
	}
}

// ownersStore is the store with ListAccounts failing when *fail is set, for the owners page.
type ownersStore struct {
	*canaryStore
	fail *bool
}

func (o *ownersStore) ListAccounts(ctx context.Context) ([]store.Account, error) {
	o.canaryStore.fail["ListAccounts"] = *o.fail
	return o.canaryStore.ListAccounts(ctx)
}

// A token create with no owner in the request is 401 identity_required and mints nothing: it minted
// a token for the node's first owner. The session gate refuses such a request before this runs, so
// the branch was unreachable in the composed portal; a mount without the gate now fails closed. The
// control, the signed-in owner, mints one.
func TestATokenCreateWithNoOwnerIsRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, err := e.st.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountOwnerPages(mux, OwnersDeps{Store: e.st, Tokens: &auth.TokenService{Store: e.st}})
	create := func(owner string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/owners/tokens/create", strings.NewReader(url.Values{"label": {"ci"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if owner != "" {
			req = signedIn(req, owner)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := create(""); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), `"identity_required"`) {
		t.Errorf("no owner: %d %s, want 401 identity_required", rr.Code, rr.Body.String())
	}
	if toks, err := e.st.ListTokens(ctx); err != nil || len(toks) != 0 {
		t.Fatalf("no owner minted %d tokens (%v)", len(toks), err)
	}
	if rr := create(owner.ID); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"new_token":"hdtp_`) {
		t.Fatalf("the control: %d %s", rr.Code, rr.Body.String())
	}
}
