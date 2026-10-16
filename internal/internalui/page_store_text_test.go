package internalui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// canaryStore is the real store with the named methods made to fail with driver text.
type canaryStore struct {
	store.Store
	fail map[string]bool
}

func (c *canaryStore) err(m string) error {
	if c.fail[m] {
		return fmt.Errorf("%s: %w", m, errors.New(pageCanary))
	}
	return nil
}

func (c *canaryStore) GetContact(ctx context.Context, a, fpr string) (store.Contact, error) {
	if err := c.err("GetContact"); err != nil {
		return store.Contact{}, err
	}
	return c.Store.GetContact(ctx, a, fpr)
}

func (c *canaryStore) InsertToken(ctx context.Context, id, owner, label string, sum []byte, account string, at int64) error {
	if err := c.err("InsertToken"); err != nil {
		return err
	}
	return c.Store.InsertToken(ctx, id, owner, label, sum, account, at)
}

func (c *canaryStore) GetIntegrationByID(ctx context.Context, id string) (store.Integration, error) {
	if err := c.err("GetIntegrationByID"); err != nil {
		return store.Integration{}, err
	}
	return c.Store.GetIntegrationByID(ctx, id)
}

func (c *canaryStore) GetAccountIntegration(ctx context.Context, a, id string) (store.Integration, error) {
	if err := c.err("GetAccountIntegration"); err != nil {
		return store.Integration{}, err
	}
	return c.Store.GetAccountIntegration(ctx, a, id)
}

// Every route that names an integration answers a read of it that failed 500 with the fixed phrase,
// and no store text: it answered 404, as for an integration not on the account. An id the account
// does not hold stays 404, and the control, the integration read, gets through.
func TestAnIntegrationThatCouldNotBeReadIs500(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, _ := e.st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://x/mcp"})
	seedCatalog(t, e.st, in.ID)
	get := func(fail bool, id string) *httptest.ResponseRecorder {
		cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetAccountIntegration": fail}}
		mux := http.NewServeMux()
		MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t), Store: cs, Manager: &integrations.Manager{Store: cs},
			Connector: &integrations.Connector{}, Exposures: &integrations.Exposures{Store: cs}, Audit: func(string, string, string) {}})
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations/"+id+"/exposure?account="+a.ID, nil))
		return rr
	}
	if rr := get(true, in.ID); rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), refusal.InternalDetail) || strings.Contains(rr.Body.String(), pageCanary) {
		t.Errorf("a read that failed: %d %s, want 500 with the fixed phrase", rr.Code, rr.Body.String())
	}
	if rr := get(false, "no-such-integration"); rr.Code != http.StatusNotFound {
		t.Errorf("an id the account does not hold: %d %s, want 404", rr.Code, rr.Body.String())
	}
	if rr := get(false, in.ID); rr.Code != http.StatusOK {
		t.Errorf("the control: %d %s", rr.Code, rr.Body.String())
	}
}

// Every portal page that showed err.Error() shows a fixed phrase for a store failure, and no store
// text, whether the failure came from the store under a domain service or from a function the page
// was handed. Each row's control, the same request with nothing failing, gets through: it shows
// neither the phrase nor the canary.
func TestEveryPageShowsNoStoreText(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := e.st.CreateOwnerWithID(ctx, "", "Owner")
	in, _ := e.st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://x/mcp"})
	seedCatalog(t, e.st, in.ID)
	now := time.Now().Unix()
	for fpr, status := range map[string]string{"sha256:asks": "pending_in", "sha256:asks2": "pending_in", "sha256:held": "active",
		"sha256:held2": "active", "sha256:blocked": "blocked"} {
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: status, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	canary := fmt.Errorf("saving: %w", errors.New(pageCanary))
	failIf := func(fail bool) error {
		if fail {
			return canary
		}
		return nil
	}
	post := func(mux *http.ServeMux, path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	acct := "?account=" + a.ID
	settings := func(fail bool) SettingsDeps {
		return SettingsDeps{
			Effective:    func() []core.Effective { return []core.Effective{{Key: "seal"}} },
			Save:         func(context.Context, []SettingValue) error { return failIf(fail) },
			SaveStorage:  func(context.Context, string, int64, int, int) error { return failIf(fail) },
			SavePreset:   func(context.Context, string, []string) error { return failIf(fail) },
			DeletePreset: func(context.Context, string) error { return failIf(fail) },
			Pair: func(context.Context, PairInput) (PairResult, error) {
				return PairResult{PublicName: "me.example", Adapter: "x"}, failIf(fail)
			},
			Unpair: func(context.Context, string) error { return failIf(fail) },
		}
	}
	rows := []struct {
		name string
		run  func(fail bool) *httptest.ResponseRecorder
	}{
		{"settings save", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings", url.Values{"seal": {"optional"}})
		}},
		{"settings storage", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings/storage", url.Values{"account": {a.ID}, "quota_gib": {"1"}, "retention_days": {"0"}, "request_expiry_days": {"7"}})
		}},
		{"settings preset", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings/presets", url.Values{"name": {"team"}, "perm": {"message.text"}})
		}},
		{"settings preset delete", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings/presets/team/delete", url.Values{})
		}},
		{"settings pair", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings/pair", url.Values{"pair_url": {"https://ingress.example/pair"}, "token": {"t"}, "subdomain": {"me"}})
		}},
		{"settings unpair", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountSettingsPages(mux, settings(fail))
			return post(mux, "/settings/unpair", url.Values{"adapter": {"x"}})
		}},
		{"identity create", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountIdentityPages(mux, IdentityDeps{
				Accounts: func(context.Context) ([]store.Account, error) { return nil, nil },
				Create: func(_ context.Context, slug, name, _ string) (store.Account, error) {
					return store.Account{ID: "x", Slug: slug, DisplayName: name}, failIf(fail)
				},
			})
			return post(mux, "/identity/create", url.Values{"slug": {"bob"}, "name": {"Bob"}})
		}},
		{"media fetch", func(fail bool) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			MountMediaPages(mux, MediaDeps{Store: e.st, Fetch: func(context.Context, string, string) (string, error) { return "h", failIf(fail) }})
			return post(mux, "/media/fetch", url.Values{"account": {a.ID}, "message": {"m1"}})
		}},
		{"owners token create", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"InsertToken": fail}}
			mux := http.NewServeMux()
			MountOwnerPages(mux, OwnersDeps{Store: e.st, Tokens: &auth.TokenService{Store: cs}})
			req := httptest.NewRequest("POST", "/owners/tokens/create", strings.NewReader(url.Values{"label": {"ci"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, signedIn(req, owner.ID))
			return rr
		}},
		{"requests approve", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetContact": fail}}
			mux := http.NewServeMux()
			MountManagePages(mux, ManageDeps{Store: cs, Contacts: &contacts.Manager{Store: cs}, Audit: func(string, string, string) {}})
			return post(mux, "/requests/sha256:asks/approve"+acct, url.Values{})
		}},
		{"requests reject", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetContact": fail}}
			mux := http.NewServeMux()
			MountManagePages(mux, ManageDeps{Store: cs, Contacts: &contacts.Manager{Store: cs}, Audit: func(string, string, string) {}})
			return post(mux, "/requests/sha256:asks2/reject"+acct, url.Values{})
		}},
		{"contact remove", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetContact": fail}}
			mux := http.NewServeMux()
			MountContactPages(mux, ContactsDeps{Store: cs})
			return post(mux, "/contacts/sha256:held/remove"+acct, url.Values{"account": {a.ID}})
		}},
		{"contact block", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetContact": fail}}
			mux := http.NewServeMux()
			MountContactPages(mux, ContactsDeps{Store: cs})
			return post(mux, "/contacts/sha256:held2/block"+acct, url.Values{"account": {a.ID}})
		}},
		{"contact unblock", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetContact": fail}}
			mux := http.NewServeMux()
			MountContactPages(mux, ContactsDeps{Store: cs})
			return post(mux, "/contacts/sha256:blocked/unblock"+acct, url.Values{"account": {a.ID}})
		}},
		{"exposure publish", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetIntegrationByID": fail}}
			mux := http.NewServeMux()
			MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t), Store: e.st, Manager: &integrations.Manager{Store: e.st},
				Connector: &integrations.Connector{}, Exposures: &integrations.Exposures{Store: cs}, Audit: func(string, string, string) {}})
			return post(mux, "/integrations/"+in.ID+"/exposure"+acct, url.Values{"expose_get_freebusy": {"1"}})
		}},
		{"exposure reconfirm", func(fail bool) *httptest.ResponseRecorder {
			cs := &canaryStore{Store: e.st, fail: map[string]bool{"GetIntegrationByID": fail}}
			mux := http.NewServeMux()
			MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t), Store: e.st, Manager: &integrations.Manager{Store: e.st},
				Connector: &integrations.Connector{}, Exposures: &integrations.Exposures{Store: cs}, Audit: func(string, string, string) {}})
			return post(mux, "/integrations/"+in.ID+"/reconfirm"+acct, url.Values{})
		}},
	}
	for _, c := range rows {
		shownText := func(rr *httptest.ResponseRecorder) string {
			loc, _ := url.QueryUnescape(rr.Header().Get("Location"))
			return rr.Body.String() + " " + loc
		}
		failed := shownText(c.run(true))
		if strings.Contains(failed, pageCanary) || strings.Contains(failed, "relation") {
			t.Errorf("%s: store text on the page: %s", c.name, failed)
		}
		if !strings.Contains(failed, refusal.InternalDetail) {
			t.Errorf("%s: the failure did not reach the page as the fixed phrase: %s", c.name, failed)
		}
		if ok := shownText(c.run(false)); strings.Contains(ok, refusal.InternalDetail) || strings.Contains(ok, pageCanary) {
			t.Errorf("%s: the control did not get through: %s", c.name, ok)
		}
	}
}
