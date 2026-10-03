package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

type auditRec struct {
	mu   sync.Mutex
	rows []string
}

func (a *auditRec) fn(action, resource, outcome string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, action+" "+resource+" "+outcome)
}

// hasRow reports a row that names this action, touched this resource and ended
// this way. The account the row is attributed to sits between the action and
// the resource, so the three parts are matched independently rather than as one
// run-together string.
func (a *auditRec) hasRow(action, resource, outcome string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.rows {
		if strings.HasPrefix(r, action+" ") && strings.Contains(r, " "+resource+" ") &&
			strings.HasSuffix(r, " "+outcome) {
			return true
		}
	}
	return false
}

func (a *auditRec) has(sub string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.rows {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// fakeUpstream is an in-process MCP server over streamable HTTP whose reachability
// can be flipped: down => every request 503s, exactly like a dead host behind a
// proxy. Sessions survive because the MCP handler instance persists.
func fakeUpstream(t *testing.T) (url string, down *atomic.Bool) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-cal", Version: "0"}, nil)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	down = &atomic.Bool{}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)
	return hs.URL, down
}

func env(t *testing.T) (*Manager, store.Store, *auditRec, store.Integration) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	url, down := fakeUpstream(t)
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: url,
	})
	if err != nil {
		t.Fatal(err)
	}
	aud := &auditRec{}
	m := &Manager{Store: st, Audit: aud.fn, WithholdAfter: 2, PingEvery: -1}
	t.Cleanup(func() { _ = m.Disconnect(context.Background(), in.ID) })
	_ = down // reachable via closure in tests that need it
	testDown[t.Name()] = down
	return m, st, aud, in
}

// testDown lets env hand each test its upstream's kill switch.
var testDown = map[string]*atomic.Bool{}

func TestConnectDisconnectReflectedInStatus(t *testing.T) {
	m, st, aud, in := env(t)
	ctx := context.Background()

	if m.Available(in.ID) {
		t.Fatal("available before connect")
	}
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetIntegrationByID(ctx, in.ID)
	if got.Status != "ok" || !m.Available(in.ID) || m.Session(in.ID) == nil {
		t.Fatalf("after connect: %+v available=%v", got, m.Available(in.ID))
	}
	if !aud.hasRow("integration_connect", "integration:cal", "ok") {
		t.Fatalf("connect not audited: %v", aud.rows)
	}
	if err := m.Disconnect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetIntegrationByID(ctx, in.ID)
	if got.Status != "disabled" || m.Available(in.ID) || m.Session(in.ID) != nil {
		t.Fatalf("after disconnect: %+v", got)
	}
	if !aud.hasRow("integration_disconnect", "integration:cal", "ok") {
		t.Fatalf("disconnect not audited: %v", aud.rows)
	}
}

func TestConnectFailureAudited(t *testing.T) {
	m, st, aud, in := env(t)
	ctx := context.Background()
	testDown[t.Name()].Store(true)
	if err := m.Connect(ctx, in.ID); err == nil {
		t.Fatal("connect to a dead upstream succeeded")
	}
	got, _ := st.GetIntegrationByID(ctx, in.ID)
	if got.Status != "unreachable" {
		t.Fatalf("status: %s", got.Status)
	}
	if !aud.hasRow("integration_connect", "integration:cal", "error") {
		t.Fatalf("failed connect not audited: %v", aud.rows)
	}
}

func TestPingFailureWithholdsThenReconnectRestores(t *testing.T) {
	m, st, aud, in := env(t)
	ctx := context.Background()
	down := testDown[t.Name()]
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	var events []string
	var evMu sync.Mutex
	m.OnAvailability = func(id string, withheld bool) {
		evMu.Lock()
		defer evMu.Unlock()
		events = append(events, map[bool]string{true: "withhold", false: "restore"}[withheld]+":"+id)
	}

	// outage: first failure => unavailable + status unreachable, tools NOT yet withheld
	down.Store(true)
	if err := m.HealthCheck(ctx, in.ID); err == nil {
		t.Fatal("health check passed while down")
	}
	got, _ := st.GetIntegrationByID(ctx, in.ID)
	if got.Status != "unreachable" || m.Available(in.ID) || m.Withheld(in.ID) {
		t.Fatalf("first failure: status=%s available=%v withheld=%v", got.Status, m.Available(in.ID), m.Withheld(in.ID))
	}
	if !aud.hasRow("integration_health", "integration:cal", "error") {
		t.Fatalf("failure not audited: %v", aud.rows)
	}
	// second consecutive failure crosses WithholdAfter=2 => withheld + announced
	_ = m.HealthCheck(ctx, in.ID)
	if !m.Withheld(in.ID) || !aud.hasRow("integration_withhold", "integration:cal", "ok") {
		t.Fatalf("not withheld after threshold: %v", aud.rows)
	}
	evMu.Lock()
	if len(events) != 1 || events[0] != "withhold:"+in.ID {
		t.Fatalf("availability events: %v", events)
	}
	evMu.Unlock()

	// recovery: upstream returns; the next cycle reconnects and restores
	down.Store(false)
	if err := m.HealthCheck(ctx, in.ID); err != nil {
		t.Fatalf("health check after recovery: %v", err)
	}
	got, _ = st.GetIntegrationByID(ctx, in.ID)
	if got.Status != "ok" || !m.Available(in.ID) || m.Withheld(in.ID) {
		t.Fatalf("after recovery: status=%s available=%v withheld=%v", got.Status, m.Available(in.ID), m.Withheld(in.ID))
	}
	if !aud.hasRow("integration_recover", "integration:cal", "ok") || !aud.hasRow("integration_restore", "integration:cal", "ok") {
		t.Fatalf("recovery not audited: %v", aud.rows)
	}
	evMu.Lock()
	if len(events) != 2 || events[1] != "restore:"+in.ID {
		t.Fatalf("availability events: %v", events)
	}
	evMu.Unlock()
}

func TestUnknownTransportRefused(t *testing.T) {
	m, st, _, in := env(t)
	ctx := context.Background()
	if err := st.UpdateIntegrationConfig(ctx, in.ID, "carrier-pigeon", "", "", "none"); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect(ctx, in.ID); err == nil || !strings.Contains(err.Error(), "unknown transport") {
		t.Fatalf("unknown transport accepted: %v", err)
	}
}
