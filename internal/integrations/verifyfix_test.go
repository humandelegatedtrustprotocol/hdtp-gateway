package integrations

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// flakyStore fails LatestExposure with a NON-ErrNoRows error once armed.
type flakyStore struct {
	store.Store
	fail atomic.Bool
}

func (f *flakyStore) LatestExposure(ctx context.Context, id string) (store.Exposure, error) {
	if f.fail.Load() {
		return store.Exposure{}, errors.New("store: database is locked")
	}
	return f.Store.LatestExposure(ctx, id)
}

func TestReconcilePropagatesStoreErrors(t *testing.T) {
	e, c, _, id := exposureEnv(t)
	ctx := context.Background()
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); err != nil {
		t.Fatal(err)
	}
	fs := &flakyStore{Store: e.Store}
	e.Store = fs
	fs.fail.Store(true)
	if _, _, err := e.Reconcile(ctx, id); err == nil {
		t.Fatal("transient store error skipped the stale guard silently")
	}
	_ = c
	fs.fail.Store(false)
	// with the store healthy, an integration with NOTHING exposed is still a no-op
	st := e.Store
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "O", Algo: "p256"})
	in2, _ := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "x", Transport: "sse", Endpoint: "https://x"})
	if _, minted, err := e.Reconcile(ctx, in2.ID); err != nil || minted {
		t.Fatalf("nothing-exposed reconcile: minted=%v err=%v", minted, err)
	}
}

func TestExposedNamesUniqueAcrossAccount(t *testing.T) {
	e, _, _, id := exposureEnv(t)
	ctx := context.Background()
	st := e.Store
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); err != nil {
		t.Fatal(err)
	}
	// a second integration in the SAME account claims the same exposed name
	in, _ := st.GetIntegrationByID(ctx, id)
	in2, _ := st.InsertIntegration(ctx, store.Integration{AccountID: in.AccountID, Slug: "cal2", Transport: "sse", Endpoint: "https://x"})
	cat, _ := st.LatestCatalog(ctx, id)
	_, _ = st.InsertCatalog(ctx, store.Catalog{IntegrationID: in2.ID, Version: 1, Tools: cat.Tools})
	if _, err := e.Publish(ctx, in2.ID, []ExposureEntry{{Tool: "create_event", Mode: ModePassthrough, ExposedName: "cal_find_slots"}}); err == nil {
		t.Fatal("name collision across integrations accepted")
	}
	// a different account may reuse it
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "O", Algo: "p256"})
	in3, _ := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "cal", Transport: "sse", Endpoint: "https://x"})
	_, _ = st.InsertCatalog(ctx, store.Catalog{IntegrationID: in3.ID, Version: 1, Tools: cat.Tools})
	if _, err := e.Publish(ctx, in3.ID, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); err != nil {
		t.Fatalf("cross-account reuse refused: %v", err)
	}
}

func TestDeliverNewestWins(t *testing.T) {
	c := &Connector{}
	c.Deliver("i1", auth.AuthorizationResult{Code: "stale"})
	c.Deliver("i1", auth.AuthorizationResult{Code: "fresh"})
	res, err := c.Fetcher("i1")(context.Background(), &auth.AuthorizationArgs{URL: "https://as/x"})
	if err != nil || res.Code != "fresh" {
		t.Fatalf("got %+v %v", res, err)
	}
}

func TestStaticCredentialStaysOnItsHost(t *testing.T) {
	var elsewhereSaw, homeSaw atomic.Pointer[string]
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("X-Api-Key")
		elsewhereSaw.Store(&v)
		w.WriteHeader(200)
	}))
	defer elsewhere.Close()
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("X-Api-Key")
		homeSaw.Store(&v)
		http.Redirect(w, r, elsewhere.URL+"/leak", http.StatusFound)
	}))
	defer home.Close()
	m := &Manager{StaticHeader: func(store.Integration) (string, string, error) { return "X-Api-Key", "s3cret", nil }}
	hc, err := m.upstreamHTTPClient(store.Integration{AuthKind: "static", Endpoint: home.URL + "/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(home.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *homeSaw.Load() != "s3cret" {
		t.Fatal("home host did not get the credential")
	}
	if got := elsewhereSaw.Load(); got == nil || *got != "" {
		t.Fatalf("credential rode the cross-host redirect: %v", got)
	}
}

func TestOAuthFailureLandsAuthError(t *testing.T) {
	as := newFakeAS(t)
	m, st, kr, in, _ := oauthEnv(t, as)
	aud := &auditRec{}
	m.Audit = aud.fn
	m.OAuthFor = func(row store.Integration) (auth.OAuthHandler, error) {
		return NewOAuthHandler(row.ID, OAuthSetup{
			Store: st, Keyring: kr, RedirectURL: "http://127.0.0.1:1/cb",
			Preregistered: &oauthex.ClientCredentials{ClientID: "pact"},
			Fetch: func(context.Context, *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
				return nil, errors.New("owner aborted authorization in the browser")
			},
		})
	}
	if err := m.Connect(context.Background(), in.ID); err == nil {
		t.Fatal("aborted authorization connected")
	}
	row, _ := st.GetIntegrationByID(context.Background(), in.ID)
	if row.Status != "auth_error" {
		t.Fatalf("status = %s, want auth_error", row.Status)
	}
	if !aud.hasRow("integration_auth", "integration:cal", "error") {
		t.Fatalf("auth failure not audited: %v", aud.rows)
	}
	// a plain network failure on a non-oauth integration stays `unreachable`
	if isAuthError(errors.New("dial tcp: connection refused")) {
		t.Fatal("network error classified as auth")
	}
}

func TestSupervisorConfigIsRaceFree(t *testing.T) {
	sup := &Supervisor{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			sup.SetConfig(StdioConfig{Command: "/usr/bin/env", MaxRestarts: i + 1, FailureWindow: time.Minute})
		}(i)
		go func() {
			defer wg.Done()
			_, _ = sup.BuildCmd()
			_ = sup.Gate()
			sup.NoteFailure()
		}()
	}
	wg.Wait()
	_ = mcp.Implementation{} // keep the mcp import honest for future cases
}
