package internalui

import (
	"context"
	"net/http"
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
	fail := false
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
