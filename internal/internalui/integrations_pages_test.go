package internalui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

func integrationsEnv(t *testing.T) (*http.ServeMux, store.Store, *integrations.Connector, string) {
	t.Helper()
	mux, st, conn, acct, _ := integrationsEnvAudited(t)
	return mux, st, conn, acct
}

// integrationsEnvAudited is integrationsEnv with the rows the pages audit.
func integrationsEnvAudited(t *testing.T) (*http.ServeMux, store.Store, *integrations.Connector, string, *[]string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ip.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	conn := &integrations.Connector{}
	mux := http.NewServeMux()
	var rows []string
	MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t),
		Store: st, Manager: &integrations.Manager{Store: st}, Connector: conn,
		ConnectTimeout: 2 * time.Second,
		Audit:          func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" "+outcome) },
	})
	return mux, st, conn, a.ID, &rows
}

func TestIntegrationCreateListAndConnectRedirect(t *testing.T) {
	mux, st, conn, acct := integrationsEnv(t)
	ctx := context.Background()

	rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {"gcal"}, "transport": {"streamable-http"},
		"endpoint": {"https://cal.example/mcp"}, "auth_kind": {"oauth"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create: %d", rr.Code)
	}
	in, err := st.GetIntegration(ctx, acct, "gcal")
	if err != nil || in.AuthKind != "oauth" {
		t.Fatalf("row: %+v %v", in, err)
	}
	// duplicate slug → conflict
	if rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {"gcal"}, "transport": {"sse"}, "endpoint": {"https://cal.example/sse"},
	}); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/integrations?account="+acct, nil))
	if rr2.Code != 200 || !strings.Contains(rr2.Body.String(), "gcal") {
		t.Fatalf("list: %d %s", rr2.Code, rr2.Body.String())
	}

	// a pending OAuth flow publishes its AS URL; /authorize bounces there
	fetchDone := make(chan *sdkauth.AuthorizationResult, 1)
	go func() {
		res, _ := conn.Fetcher(in.ID)(ctx, &sdkauth.AuthorizationArgs{URL: "https://as.example/authorize?x=1&state=s1"})
		fetchDone <- res
	}()
	deadline := time.Now().Add(2 * time.Second)
	var loc string
	for time.Now().Before(deadline) {
		rr3 := httptest.NewRecorder()
		mux.ServeHTTP(rr3, httptest.NewRequest("GET", "/integrations/"+in.ID+"/authorize?account="+acct, nil))
		if rr3.Code == http.StatusSeeOther {
			loc = rr3.Header().Get("Location")
			break
		}
	}
	if loc != "https://as.example/authorize?x=1&state=s1" {
		t.Fatalf("authorize redirect: %q", loc)
	}
	// the AS calls back; the waiting fetcher receives code/state/iss verbatim
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, httptest.NewRequest("GET",
		"/oauth/callback?code=c1&state=s1&iss=https%3A%2F%2Fas.example", nil))
	if rr4.Code != 200 {
		t.Fatalf("callback: %d", rr4.Code)
	}
	select {
	case res := <-fetchDone:
		if res == nil || res.Code != "c1" || res.State != "s1" || res.Iss != "https://as.example" {
			t.Fatalf("delivered result: %+v", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("fetcher never received the callback")
	}
}

func seedCatalog(t *testing.T, st store.Store, integrationID string) {
	t.Helper()
	tools := []integrations.ToolDef{
		{Name: "get_freebusy", Description: "Read availability",
			Annotations: []byte(`{"readOnlyHint":true,"destructiveHint":false}`), Hash: "h-read"},
		{Name: "delete_event", Description: "Delete an event", Hash: "h-del"},
	}
	blob, _ := json.Marshal(tools)
	if _, err := st.InsertCatalog(context.Background(), store.Catalog{
		IntegrationID: integrationID, Version: 1, Tools: string(blob),
	}); err != nil {
		t.Fatal(err)
	}
}

func pickerEnv(t *testing.T) (*http.ServeMux, store.Store, *recAudit, store.Integration) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://x/mcp",
	})
	seedCatalog(t, st, in.ID)
	aud := &recAudit{}
	mux := http.NewServeMux()
	MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t),
		Store: st, Manager: &integrations.Manager{Store: st}, Connector: &integrations.Connector{},
		Exposures: &integrations.Exposures{Store: st, Audit: aud.fn}, Audit: aud.fn,
	})
	return mux, st, aud, in
}

func TestPickerRendersRiskSortedAndEmptyByDefault(t *testing.T) {
	mux, _, _, in := pickerEnv(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations/"+in.ID+"/exposure?account="+in.AccountID, nil))
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("picker: %d", rr.Code)
	}
	var page struct {
		Tools []struct {
			Name string `json:"name"`
			Risk struct {
				Write bool `json:"write"`
			} `json:"risk"`
			Suggestion string `json:"suggestion"`
			Exposed    bool   `json:"exposed"`
		} `json:"tools"`
		Entries  []any `json:"entries"`
		HasStale bool  `json:"has_stale"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatalf("picker is not JSON: %v — %s", err, body)
	}
	// nothing exposed by default
	if len(page.Entries) != 0 {
		t.Fatalf("entries not empty by default: %d", len(page.Entries))
	}
	for _, tool := range page.Tools {
		if tool.Exposed {
			t.Fatalf("%s exposed by default", tool.Name)
		}
	}
	// risk sort: read-only tools before write-capable ones — the ARRAY ORDER is
	// the sort the view renders, so it is the thing to assert.
	ro, del := -1, -1
	for i, tool := range page.Tools {
		switch tool.Name {
		case "get_freebusy":
			ro = i
		case "delete_event":
			del = i
			if !tool.Risk.Write {
				t.Fatal("delete_event not marked write-capable")
			}
		}
	}
	if ro < 0 || del < 0 || ro > del {
		t.Fatalf("risk sort: freebusy@%d delete@%d", ro, del)
	}
	// recipe pre-selection carried for the availability-shaped tool
	found := false
	for _, tool := range page.Tools {
		if tool.Suggestion == "check_availability" {
			found = true
		}
	}
	if !found {
		t.Fatal("recipe suggestion missing")
	}
}

func TestExposingDestructiveToolNeedsRecordedAck(t *testing.T) {
	mux, st, aud, in := pickerEnv(t)
	ctx := context.Background()

	// no ack → refused, nothing exposed
	rr := postForm(t, mux, "/integrations/"+in.ID+"/exposure?account="+in.AccountID, url.Values{
		"expose_delete_event": {"1"}, "mode_delete_event": {"passthrough"},
	})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "write-capable") {
		t.Fatalf("no-ack accepted: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := st.LatestExposure(ctx, in.ID); err == nil {
		t.Fatal("exposure published without ack")
	}
	// with ack → published + BOTH audit rows (ack records which tools)
	rr = postForm(t, mux, "/integrations/"+in.ID+"/exposure?account="+in.AccountID, url.Values{
		"expose_delete_event": {"1"}, "mode_delete_event": {"passthrough"}, "ack": {"1"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("ack publish: %d %s", rr.Code, rr.Body.String())
	}
	exp, err := st.LatestExposure(ctx, in.ID)
	if err != nil || exp.Version != 1 {
		t.Fatalf("exposure: %+v %v", exp, err)
	}
	if !aud.hasRow("exposure_ack", "integration:cal ack:delete_event", "ok") {
		t.Fatalf("ack not audited: %v", aud.rows)
	}
	if !aud.hasRow("exposure_publish", "integration:cal exposure:v1", "ok") {
		t.Fatalf("publish not audited: %v", aud.rows)
	}
	// read-only tool needs no ack
	rr = postForm(t, mux, "/integrations/"+in.ID+"/exposure?account="+in.AccountID, url.Values{
		"expose_get_freebusy": {"1"}, "mode_get_freebusy": {"passthrough"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("read-only needed ack: %d %s", rr.Code, rr.Body.String())
	}
}

func TestManualRefreshRouteSnapshotsCatalog(t *testing.T) {
	// a real (tiny) MCP upstream so the manager can connect and list tools
	srv := mcp.NewServer(&mcp.Implementation{Name: "up", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "ping_me", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	defer hs.Close()

	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "rf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "up", Transport: "streamable-http", Endpoint: hs.URL,
	})
	m := &integrations.Manager{Store: st, PingEvery: -1}
	defer func() { _ = m.Disconnect(context.Background(), in.ID) }()
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t),
		Store: st, Manager: m, Connector: &integrations.Connector{},
		Exposures: &integrations.Exposures{Store: st},
		Cataloger: &integrations.Cataloger{Store: st, Manager: m},
	})
	rr := postForm(t, mux, "/integrations/"+in.ID+"/refresh?account="+a.ID, url.Values{})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("refresh: %d %s", rr.Code, rr.Body.String())
	}
	cat, err := st.LatestCatalog(ctx, in.ID)
	if err != nil || cat.Version != 1 || !strings.Contains(cat.Tools, "ping_me") {
		t.Fatalf("catalog after refresh: %+v %v", cat, err)
	}
	// unwired cataloger → 409, never a silent no-op
	mux2 := http.NewServeMux()
	MountIntegrationPages(mux2, IntegrationsDeps{Background: joined(t), Store: st, Manager: m, Connector: &integrations.Connector{}, Exposures: &integrations.Exposures{Store: st}})
	if rr := postForm(t, mux2, "/integrations/"+in.ID+"/refresh?account="+a.ID, url.Values{}); rr.Code != http.StatusConflict {
		t.Fatalf("unwired refresh: %d", rr.Code)
	}
}

func TestPickerShowsStaleAndReconfirmRestores(t *testing.T) {
	mux, st, _, in := pickerEnv(t)
	ctx := context.Background()
	exps := &integrations.Exposures{Store: st}
	if _, err := exps.Publish(ctx, in.ID, []integrations.ExposureEntry{{Tool: "get_freebusy", Mode: integrations.ModePassthrough}}); err != nil {
		t.Fatal(err)
	}
	// the upstream definition drifts: catalog v2 with a new hash → guard trips
	tools := []integrations.ToolDef{
		{Name: "get_freebusy", Description: "changed", Hash: "h-read-2"},
		{Name: "delete_event", Description: "Delete an event", Hash: "h-del"},
	}
	blob, _ := json.Marshal(tools)
	if _, err := st.InsertCatalog(ctx, store.Catalog{IntegrationID: in.ID, Version: 2, Tools: string(blob)}); err != nil {
		t.Fatal(err)
	}
	if _, minted, err := exps.Reconcile(ctx, in.ID); err != nil || !minted {
		t.Fatalf("reconcile: minted=%v err=%v", minted, err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations/"+in.ID+"/exposure?account="+in.AccountID, nil))
	body := rr.Body.String()
	// The API must SAY it is stale; the recovery affordance ships in the bundle.
	if !strings.Contains(body, `"has_stale":true`) || !strings.Contains(body, `"stale":true`) {
		t.Fatalf("stale entry invisible in the picker payload:\n%s", body)
	}
	if js := bundleJS(t); !strings.Contains(js, "Reconfirm all stale") || !strings.Contains(js, "/reconfirm") {
		t.Fatal("the compiled portal offers no way to reconfirm a stale exposure")
	}
	// one-click reconfirm (all) → served again
	rr2 := postForm(t, mux, "/integrations/"+in.ID+"/reconfirm?account="+in.AccountID, url.Values{})
	if rr2.Code != http.StatusSeeOther {
		t.Fatalf("reconfirm: %d %s", rr2.Code, rr2.Body.String())
	}
	active, _ := exps.ActiveEntries(ctx, in.ID)
	if len(active) != 1 || active[0].ConfirmedHash != "h-read-2" {
		t.Fatalf("reconfirm did not restore: %+v", active)
	}
}

func TestIntegrationListOffersReconnectOnAuthError(t *testing.T) {
	mux, st, _, acct := integrationsEnv(t)
	in, _ := st.InsertIntegration(context.Background(), store.Integration{
		AccountID: acct, Slug: "gcal", Transport: "streamable-http", Endpoint: "https://x/mcp", AuthKind: "oauth",
	})
	_ = st.UpdateIntegrationStatus(context.Background(), in.ID, "auth_error")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations?account="+acct, nil))
	if !strings.Contains(rr.Body.String(), `"Status":"auth_error"`) {
		t.Fatalf("auth_error not surfaced to the portal:\n%s", rr.Body.String())
	}
	if js := bundleJS(t); !strings.Contains(js, "Reconnect") || !strings.Contains(js, "authorization failed") {
		t.Fatal("the compiled portal cannot say an integration needs reconnecting")
	}
}

// The portal's Connect & authorize asks for JSON and navigates to the provider
// by script. It used to submit a form answered with a redirect to the AS, which
// the portal's own CSP blocks: `form-action 'self'` covers where a submission
// ends up, redirects included. A JSON answer carries the URL instead.
func TestConnectAnswersTheAuthorizeURLAsJSON(t *testing.T) {
	mux, st, conn, acct := integrationsEnv(t)
	ctx := context.Background()
	if rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {"gcal"}, "transport": {"streamable-http"},
		"endpoint": {"https://cal.example/mcp"}, "auth_kind": {"oauth"},
	}); rr.Code != http.StatusSeeOther {
		t.Fatalf("create: %d", rr.Code)
	}
	in, _ := st.GetIntegration(ctx, acct, "gcal")
	published := make(chan struct{})
	go func() {
		close(published)
		_, _ = conn.Fetcher(in.ID)(ctx, &sdkauth.AuthorizationArgs{URL: "https://as.example/authorize?x=2"})
	}()
	<-published
	deadline := time.Now().Add(2 * time.Second)
	var got map[string]any
	for time.Now().Before(deadline) {
		req := httptest.NewRequest("POST", "/integrations/"+in.ID+"/connect?account="+acct, strings.NewReader("csrf=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == 200 {
			_ = json.Unmarshal(rr.Body.Bytes(), &got)
			break
		}
	}
	if got["authorize_url"] != "https://as.example/authorize?x=2" {
		t.Fatalf("JSON connect did not carry the authorization URL: %v", got)
	}

	// a non-OAuth integration has no provider to visit: plain ok
	if rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {"notes"}, "transport": {"streamable-http"},
		"endpoint": {"https://notes.example/mcp"}, "auth_kind": {"none"},
	}); rr.Code != http.StatusSeeOther {
		t.Fatalf("create notes: %d", rr.Code)
	}
	notes, _ := st.GetIntegration(ctx, acct, "notes")
	req := httptest.NewRequest("POST", "/integrations/"+notes.ID+"/connect?account="+acct, strings.NewReader("csrf=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("non-OAuth JSON connect: %d %s", rr.Code, rr.Body.String())
	}
}

// The provider calls back with the registered redirect URI verbatim plus code and state — never
// with our integration id. The callback used to demand `integration=` and answered a real provider
// with 400 "missing integration"; then it took `integration=` when given, which the route serves
// with no session: a GET naming any id made the connector a flow entry for it, one naming a
// pending integration with a foreign state ended the owner's pending connect, and the row it
// wrote took its account from the query. The state the node minted is the whole authority.
func TestCallbackFindsTheFlowByStateAlone(t *testing.T) {
	mux, st, conn, acct, rows := integrationsEnvAudited(t)
	ctx := context.Background()
	if rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {"gcal"}, "transport": {"streamable-http"},
		"endpoint": {"https://cal.example/mcp"}, "auth_kind": {"oauth"},
	}); rr.Code != http.StatusSeeOther {
		t.Fatalf("create: %d", rr.Code)
	}
	in, _ := st.GetIntegration(ctx, acct, "gcal")
	got := make(chan *sdkauth.AuthorizationResult, 1)
	go func() {
		res, _ := conn.Fetcher(in.ID)(ctx, &sdkauth.AuthorizationArgs{URL: "https://as.example/authorize?client_id=c&state=S7&redirect_uri=http%3A%2F%2Flocalhost%3A18120%2Foauth%2Fcallback"})
		got <- res
	}()
	// The fetcher publishes its URL once the state is remembered.
	if _, err := conn.AuthorizeURL(ctx, in.ID, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	*rows = nil
	callback := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/oauth/callback?"+query, nil))
		return rr
	}

	// A state the node did not mint names nothing: refused, no row, and the pending flow is not
	// touched — naming the pending integration, or any other id, changes none of that.
	for _, query := range []string{"code=x&state=NOPE", "integration=" + in.ID + "&code=x&state=NOPE",
		"integration=ghost&code=x&state=NOPE&account=" + acct, "code=x"} {
		if rr := callback(query); rr.Code != http.StatusBadRequest {
			t.Errorf("callback ?%s: %d, want 400", query, rr.Code)
		}
	}
	if len(*rows) != 0 {
		t.Errorf("a callback for a state the node did not mint was audited: %v", *rows)
	}
	select {
	case res := <-got:
		t.Fatalf("a foreign state ended the owner's pending connect: %+v", res)
	case <-time.After(300 * time.Millisecond):
	}

	// The control: the state the flow was minted with completes it, once, under its own account.
	if rr := callback("code=c9&state=S7"); rr.Code != 200 {
		t.Fatalf("callback with the minted state: %d %s", rr.Code, rr.Body.String())
	}
	select {
	case res := <-got:
		if res == nil || res.Code != "c9" || res.State != "S7" {
			t.Fatalf("fetcher got %+v", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the waiting fetcher never received the code")
	}
	if want := "integration_oauth_callback account:" + acct + " integration:" + in.ID + " ok"; len(*rows) != 1 || (*rows)[0] != want {
		t.Errorf("rows %v, want [%s]", *rows, want)
	}
	if rr := callback("code=c9&state=S7"); rr.Code != http.StatusBadRequest {
		t.Fatalf("a delivered state was accepted again: %d", rr.Code)
	}
}

// The portal's Reconnect button is the owner's decision, and the one thing that re-arms at once a
// supervised child that exhausted its restarts (SPEC §6.2); otherwise it waits out its failure
// window. The button called Manager.Connect, whose Gate refuses a given-up child inside that
// window before launching anything, so it did nothing while the error it answered said
// "reconnect to retry" (review N-15). This drives the real route and
// watches for the launch: the child is /usr/bin/false, so every launch is one crash row.
func TestPortalReconnectRearmsAChildThatGaveUp(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "rc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "crashy", Transport: "stdio-supervised", Command: "/usr/bin/false",
	})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	crashes := 0
	m := &integrations.Manager{
		Store: st, PingEvery: -1, StdioSleep: func(time.Duration) {},
		Audit: func(action, _, _ string) {
			if action == "integration_child_crash" {
				mu.Lock()
				crashes++
				mu.Unlock()
			}
		},
		StdioConfigFor: func(row store.Integration) integrations.StdioConfig {
			return integrations.StdioConfig{Command: row.Command, MaxRestarts: 1, TerminateDuration: time.Second, NoShim: true}
		},
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return crashes }

	// One crash, and the child has given up.
	if err := m.Connect(ctx, in.ID); err == nil {
		t.Fatal("/usr/bin/false connected")
	}
	if err := m.Connect(ctx, in.ID); !errors.Is(err, integrations.ErrUnavailable) {
		t.Fatalf("the child did not give up after its one restart: %v", err)
	}
	if count() != 1 {
		t.Fatalf("crashes before the owner acts: %d, want 1", count())
	}

	mux := http.NewServeMux()
	MountIntegrationPages(mux, IntegrationsDeps{Background: joined(t), Store: st, Manager: m, ConnectTimeout: 2 * time.Second})
	if rr := postForm(t, mux, "/integrations/"+in.ID+"/connect?account="+a.ID, url.Values{}); rr.Code >= 400 {
		t.Fatalf("reconnect: %d %s", rr.Code, rr.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for count() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if count() < 2 {
		t.Fatal("the portal's Reconnect launched nothing: a child that gave up stays given up after the owner asked")
	}
}

// Every integration route takes the integration from the path and the account from the query, and
// accountMiddleware checks only that the signed-in owner administers the account named. Remove
// compared the row's account with the named one and refused 403; the other eight routes compared
// nothing, so an owner of account A could connect, re-credential, refresh, read and set the
// exposure of account B's integration by naming its id. Each now answers the 404 a missing row
// gets, and writes nothing. The control, the same call as B, runs last: it changes B's row.
func TestIntegrationRoutesRefuseAnotherAccountsIntegration(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	b, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "b", DisplayName: "B", Algo: "p256"})

	// What a route reached past the account check: the credential and client writers, and the
	// background work a connect starts.
	var mu sync.Mutex
	var reached []string
	note := func(what string) { mu.Lock(); defer mu.Unlock(); reached = append(reached, what) }
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(reached) }
	bg := joined(t)
	aud := &recAudit{}
	conn := &integrations.Connector{}
	m := &integrations.Manager{Store: st, PingEvery: -1}
	exps := &integrations.Exposures{Store: st, Audit: aud.fn}
	mux := http.NewServeMux()
	MountIntegrationPages(mux, IntegrationsDeps{
		Store: st, Manager: m, Connector: conn, Exposures: exps,
		Cataloger:      &integrations.Cataloger{Store: st, Manager: m},
		Audit:          aud.fn,
		ConnectTimeout: time.Second,
		SetStatic:      func(_ context.Context, id, _, _ string) error { note("static " + id); return nil },
		SetOAuthClient: func(_ context.Context, id, _, _ string) error { note("oauth-client " + id); return nil },
		Background:     func(work func(ctx context.Context)) { note("background"); bg(work) },
	})

	routes := []struct {
		name, method, path string // the path with {id} for the integration's id
		form               url.Values
	}{
		{"oauth-client", "POST", "/integrations/{id}/oauth-client", url.Values{"client_id": {"c"}, "client_secret": {"s"}}},
		{"credential", "POST", "/integrations/{id}/credential", url.Values{"header": {"Authorization"}, "value": {"v"}}},
		{"connect", "POST", "/integrations/{id}/connect", url.Values{}},
		{"authorize", "GET", "/integrations/{id}/authorize", nil},
		{"refresh", "POST", "/integrations/{id}/refresh", url.Values{}},
		{"exposure-read", "GET", "/api/integrations/{id}/exposure", nil},
		{"exposure", "POST", "/integrations/{id}/exposure", url.Values{"expose_get_freebusy": {"1"}, "mode_get_freebusy": {"passthrough"}}},
		{"reconfirm", "POST", "/integrations/{id}/reconfirm", url.Values{}},
		{"remove", "POST", "/integrations/{id}/remove", url.Values{}},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			// B's integration, with a catalog so the exposure routes have something to show, and
			// for reconfirm an exposure to reconfirm. The endpoint refuses the connection at once.
			in, err := st.InsertIntegration(ctx, store.Integration{
				AccountID: b.ID, Slug: rt.name, Transport: "streamable-http", Endpoint: "http://127.0.0.1:1/mcp",
			})
			if err != nil {
				t.Fatal(err)
			}
			seedCatalog(t, st, in.ID)
			if rt.name == "reconfirm" {
				if _, err := exps.Publish(ctx, in.ID, []integrations.ExposureEntry{{Tool: "get_freebusy", Mode: integrations.ModePassthrough}}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := st.GetIntegrationByID(ctx, in.ID)
			if err != nil {
				t.Fatal(err)
			}
			hadExposure := hasExposure(ctx, st, in.ID)
			reachedBefore, rowsBefore := count(), len(aud.rows)
			call := func(account string) *httptest.ResponseRecorder {
				path := strings.ReplaceAll(rt.path, "{id}", in.ID) + "?account=" + account
				if rt.method == "POST" {
					return postForm(t, mux, path, rt.form)
				}
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, httptest.NewRequest(rt.method, path, nil))
				return rr
			}

			// As A, naming B's integration: the answer a missing row gets, and nothing done.
			rr := call(a.ID)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("%s %s as another account: %d %s, want 404", rt.method, rt.path, rr.Code, strings.TrimSpace(rr.Body.String()))
			}
			if after, err := st.GetIntegrationByID(ctx, in.ID); err != nil || after != before {
				t.Fatalf("the row changed: before %+v, after %+v (%v)", before, after, err)
			}
			if hasExposure(ctx, st, in.ID) != hadExposure {
				t.Fatal("an exposure was written for another account's integration")
			}
			if count() != reachedBefore {
				t.Fatalf("a writer was reached for another account's integration: %v", reached[reachedBefore:])
			}
			if conn.Origin(in.ID) != "" {
				t.Fatal("the connector was told an origin for another account's integration")
			}
			// Remove's refusal stays audited as it was; no other route writes a row for it.
			switch rows := aud.rows[rowsBefore:]; rt.name {
			case "remove":
				if len(rows) != 1 || !aud.hasRow("integration_remove", "integration:"+in.ID, "refused") {
					t.Fatalf("remove's refusal audit: %v", rows)
				}
			default:
				if len(rows) != 0 {
					t.Fatalf("a refused %s wrote audit rows: %v", rt.name, rows)
				}
			}

			// The control: the same call as B gets through.
			if rr := call(b.ID); rr.Code == http.StatusNotFound {
				t.Fatalf("%s %s as the integration's own account: 404 %s", rt.method, rt.path, strings.TrimSpace(rr.Body.String()))
			}
		})
	}
}

// hasExposure reports whether the integration has a published exposure.
func hasExposure(ctx context.Context, st store.Store, integrationID string) bool {
	_, err := st.LatestExposure(ctx, integrationID)
	return err == nil
}

// joined is a test's joined background group, as serve's: the work a request starts gets the
// group's context, and the test's cleanup ends that context and waits for the work before the
// store closes and the temporary directory goes (cleanups run last-registered first, and this
// one is registered after both).
func joined(t *testing.T) func(work func(ctx context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	return func(work func(ctx context.Context)) { wg.Go(func() { work(ctx) }) }
}
