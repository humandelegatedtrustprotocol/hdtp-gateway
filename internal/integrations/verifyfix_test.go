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

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
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
	// Two authorizations minted for one flow and abandoned (their fetch ended): each state stays
	// pending until it expires, and a result for either is delivered to the flow.
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for _, state := range []string{"S1", "S2"} {
		if _, err := c.Fetcher("i1")(gone, &auth.AuthorizationArgs{URL: "https://as/x?state=" + state}); err == nil {
			t.Fatal("a fetch whose context ended returned a result")
		}
	}
	if _, ok := c.Deliver(auth.AuthorizationResult{Code: "stale", State: "S1"}); !ok {
		t.Fatal("a minted state was not delivered")
	}
	if _, ok := c.Deliver(auth.AuthorizationResult{Code: "fresh", State: "S2"}); !ok {
		t.Fatal("a minted state was not delivered")
	}
	res, err := c.Fetcher("i1")(context.Background(), &auth.AuthorizationArgs{URL: "https://as/x?state=S3"})
	if err != nil || res.Code != "fresh" {
		t.Fatalf("got %+v %v", res, err)
	}
}

// A result whose state the node did not mint names no flow: Deliver creates none (the callback
// route is served without a session, so a flow per distinct id was unbounded growth from an
// unauthenticated GET), writes to none, and a pending flow stays pending. The control is the
// state the flow was minted with.
func TestDeliverTouchesNothingForAStateItDidNotMint(t *testing.T) {
	c := &Connector{}
	for _, state := range []string{"NOPE", "", "ghost-2"} {
		if id, ok := c.Deliver(auth.AuthorizationResult{Code: "x", State: state}); ok || id != "" {
			t.Errorf("state %q was delivered to %q", state, id)
		}
	}
	if n := len(c.flows); n != 0 {
		t.Fatalf("results for states the node did not mint created %d flow entries", n)
	}
	got := make(chan *auth.AuthorizationResult, 1)
	go func() {
		res, _ := c.Fetcher("i1")(context.Background(), &auth.AuthorizationArgs{URL: "https://as/x?state=S7"})
		got <- res
	}()
	if _, err := c.AuthorizeURL(context.Background(), "i1", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Deliver(auth.AuthorizationResult{Code: "x", State: "NOPE"}); ok {
		t.Fatal("an unminted state was delivered to a pending flow")
	}
	select {
	case res := <-got:
		t.Fatalf("the pending flow was ended by an unminted state: %+v", res)
	case <-time.After(300 * time.Millisecond):
	}
	if id, ok := c.Deliver(auth.AuthorizationResult{Code: "c9", State: "S7"}); !ok || id != "i1" {
		t.Fatalf("the minted state was not delivered: %q %v", id, ok)
	}
	select {
	case res := <-got:
		if res == nil || res.Code != "c9" {
			t.Fatalf("delivered %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pending flow never received the minted state's result")
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
			Preregistered: &oauthex.ClientCredentials{ClientID: "hdtp"},
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
