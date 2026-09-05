package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

func integrationsEnv(t *testing.T) (*http.ServeMux, store.Store, *integrations.Connector, string) {
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
	MountIntegrationPages(mux, IntegrationsDeps{
		Store: st, Manager: &integrations.Manager{Store: st}, Connector: conn,
		ConnectTimeout: 2 * time.Second,
	})
	return mux, st, conn, a.ID
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
		res, _ := conn.Fetcher(in.ID)(ctx, &sdkauth.AuthorizationArgs{URL: "https://as.example/authorize?x=1"})
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
	if loc != "https://as.example/authorize?x=1" {
		t.Fatalf("authorize redirect: %q", loc)
	}
	// the AS calls back; the waiting fetcher receives code/state/iss verbatim
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, httptest.NewRequest("GET",
		"/oauth/callback?integration="+in.ID+"&code=c1&state=s1&iss=https%3A%2F%2Fas.example", nil))
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
	MountIntegrationPages(mux, IntegrationsDeps{
		Store: st, Manager: &integrations.Manager{Store: st}, Connector: &integrations.Connector{},
		Exposures: &integrations.Exposures{Store: st, Audit: aud.fn}, Audit: aud.fn,
	})
	return mux, st, aud, in
}

func TestPickerRendersRiskSortedAndEmptyByDefault(t *testing.T) {
	mux, _, _, in := pickerEnv(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations/"+in.ID+"/exposure", nil))
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
	rr := postForm(t, mux, "/integrations/"+in.ID+"/exposure", url.Values{
		"expose_delete_event": {"1"}, "mode_delete_event": {"passthrough"},
	})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "write-capable") {
		t.Fatalf("no-ack accepted: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := st.LatestExposure(ctx, in.ID); err == nil {
		t.Fatal("exposure published without ack")
	}
	// with ack → published + BOTH audit rows (ack records which tools)
	rr = postForm(t, mux, "/integrations/"+in.ID+"/exposure", url.Values{
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
	rr = postForm(t, mux, "/integrations/"+in.ID+"/exposure", url.Values{
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
	MountIntegrationPages(mux, IntegrationsDeps{
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
	MountIntegrationPages(mux2, IntegrationsDeps{Store: st, Manager: m, Connector: &integrations.Connector{}, Exposures: &integrations.Exposures{Store: st}})
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
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/integrations/"+in.ID+"/exposure", nil))
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

// The provider calls back with the registered redirect URI verbatim plus code
// and state — never with our integration id. The callback used to demand
// `integration=` and answered a real provider with 400 "missing integration".
func TestCallbackFindsTheFlowByState(t *testing.T) {
	mux, st, conn, acct := integrationsEnv(t)
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := conn.IntegrationForState("S7"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/oauth/callback?code=c9&state=S7", nil))
	if rr.Code != 200 {
		t.Fatalf("callback without integration id: %d %s", rr.Code, rr.Body.String())
	}
	select {
	case res := <-got:
		if res == nil || res.Code != "c9" || res.State != "S7" {
			t.Fatalf("fetcher got %+v", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the waiting fetcher never received the code")
	}
	if _, ok := conn.IntegrationForState("S7"); ok {
		t.Fatal("a delivered state is still pending")
	}
	// an unknown state names nothing: refused, nothing delivered
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/oauth/callback?code=x&state=NOPE", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown state accepted: %d", rr.Code)
	}
}
