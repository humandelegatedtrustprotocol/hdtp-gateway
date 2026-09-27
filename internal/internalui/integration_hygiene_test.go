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

// The Add form validated nothing, so pressing Add with the fields blank created a
// real integration row with an empty slug and no endpoint: the list then showed
// `— streamable-http — disabled`, Connect tried to dial "", and there was no way
// to remove it. `DeleteIntegration` existed in the store the whole time and had
// no route to reach it.
func TestAddingAnIntegrationRequiresSomethingToConnectTo(t *testing.T) {
	mux, st, _, _ := pickerEnv(t)
	ctx := context.Background()
	before, _ := st.ListIntegrations(ctx, accountOf(t, st))

	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"no slug at all", url.Values{"transport": {"streamable-http"}, "endpoint": {"https://x/mcp"}}},
		{"http with no endpoint", url.Values{"slug": {"a"}, "transport": {"streamable-http"}}},
		{"sse with no endpoint", url.Values{"slug": {"b"}, "transport": {"sse"}}},
		{"stdio with no command", url.Values{"slug": {"c"}, "transport": {"stdio-supervised"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/integrations/create?account="+accountOf(t, st),
				strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			mux.ServeHTTP(rr, req)
			if rr.Code == http.StatusSeeOther {
				t.Errorf("accepted: an integration with nothing to connect to was created")
			}
		})
	}
	after, _ := st.ListIntegrations(ctx, accountOf(t, st))
	if len(after) != len(before) {
		t.Errorf("%d junk integrations were created", len(after)-len(before))
	}
}

// And whatever is in the list must be removable — including a row created before
// the validation above existed.
func TestAnIntegrationCanBeRemoved(t *testing.T) {
	mux, st, _, in := pickerEnv(t)
	ctx := context.Background()

	// The row must reach the portal, and the compiled portal must offer removal.
	body := renderIntegrations(t, mux, accountOf(t, st))
	if !strings.Contains(body, in.ID) {
		t.Fatalf("the integration is invisible to the portal: %s", firstN(body, 500))
	}
	if !strings.Contains(bundleJS(t), "/remove") {
		t.Fatal("the compiled portal offers no way to remove an integration")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/integrations/"+in.ID+"/remove?account="+accountOf(t, st), nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", rr.Code)
	}
	left, _ := st.ListIntegrations(ctx, accountOf(t, st))
	for _, l := range left {
		if l.ID == in.ID {
			t.Error("the integration is still there after removing it")
		}
	}
}

// Removing one account's integration from another account must not work: the id
// is caller-supplied, and trusting it would let any account delete any row.
func TestRemoveRefusesAnIntegrationOfAnotherAccount(t *testing.T) {
	mux, st, _, in := pickerEnv(t)
	ctx := context.Background()
	owner := in.AccountID // capture BEFORE a second account exists: ListAccounts order is not ours to assume
	other, err := st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/integrations/"+in.ID+"/remove?account="+other.ID, nil)
	mux.ServeHTTP(rr, req)

	left, _ := st.ListIntegrations(ctx, owner)
	found := false
	for _, l := range left {
		if l.ID == in.ID {
			found = true
		}
	}
	if !found {
		t.Error("one account deleted another account's integration")
	}
}

func renderIntegrations(t *testing.T, mux *http.ServeMux, account string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations?account="+account, nil))
	return rr.Body.String()
}

func accountOf(t *testing.T, st store.Store) string {
	t.Helper()
	accts, err := st.ListAccounts(context.Background())
	if err != nil || len(accts) == 0 {
		t.Fatal("no account")
	}
	return accts[0].ID
}
