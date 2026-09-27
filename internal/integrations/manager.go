package integrations

// Manager owns the node's upstream MCP client connections (SPEC §6.1, §6.10):
// per-integration connect/disconnect over the SDK's struct-literal transports,
// a health cycle whose failures first make tools fail `unavailable` and then —
// past a threshold — withhold them from tools/list, and automatic reconnection
// on recovery. Every transition is audited. stdio-supervised lands with P3-02.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// DefaultWithholdAfter matches SPEC §6.10: withhold after 5 consecutive failures.
const DefaultWithholdAfter = 5

// DefaultPingEvery matches SPEC §6.10: ping every 60 s.
const DefaultPingEvery = 60 * time.Second

type Manager struct {
	Store store.IntegrationStore
	Audit func(action, resource, outcome string)
	// OnAuthError fires when a dial or health check lands in auth_error: the
	// token is dead and only the owner can fix it, so whoever is listening
	// (the change feed) should say so NOW rather than at the next poll.
	OnAuthError func(integrationID string)
	// OnAvailability fires on withhold (true) and restore (false): the serving
	// layer rebuilds per-caller servers and emits tools/list_changed (SPEC §6.10).
	OnAvailability func(integrationID string, withheld bool)
	HTTPClient     *http.Client
	// PingEvery: 0 = SPEC §6.10 default (60 s); negative disables the
	// background cycle (tests drive HealthCheck directly).
	PingEvery     time.Duration
	WithholdAfter int
	// OnConnected fires after a successful connect AND after recovery — the
	// catalog machinery takes its snapshot here (SPEC §6.3, §6.4, §6.10).
	OnConnected func(integrationID string)
	// OnHealthy fires on every healthy cycle: the periodic catalog refresh seam
	// (SPEC §6.4 "on the periodic health cycle").
	OnHealthy func(integrationID string)
	// StdioConfigFor customizes a stdio child's config (env allow-list, limits).
	// nil = StdioConfig{Command: row.Command} with defaults.
	StdioConfigFor func(in store.Integration) StdioConfig
	// StdioSleep overrides restart-backoff sleeping (tests).
	StdioSleep func(time.Duration)
	// OAuthFor supplies the per-integration OAuth handler when auth=oauth
	// (built by NewOAuthHandler; wired by serve).
	OAuthFor func(in store.Integration) (auth.OAuthHandler, error)
	// StaticHeader resolves the sealed static credential when auth=static:
	// header name + value attached to every upstream request (SPEC §6.3).
	StaticHeader func(in store.Integration) (name, value string, err error)
	// OnToolListChanged fires when a connected upstream announces
	// notifications/tools/list_changed — the catalog machinery refreshes
	// (SPEC §6.4). Standalone SSE stays enabled so this can arrive.
	OnToolListChanged func(integrationID string)

	mu    sync.Mutex
	conns map[string]*conn
	stdio map[string]*Supervisor
	loops map[string]context.CancelFunc // one health cycle per integration
}

type conn struct {
	session  *mcp.ClientSession
	failures int
	withheld bool
}

func (m *Manager) audit(action, resource, outcome string) {
	if m.Audit != nil {
		m.Audit(action, resource, outcome)
	}
}

func (m *Manager) withholdAfter() int {
	if m.WithholdAfter > 0 {
		return m.WithholdAfter
	}
	return DefaultWithholdAfter
}

// transport builds the SDK client transport for a row (SPEC §6.1). Standalone
// SSE stays enabled on streamable-http: it carries tools/list_changed (§6.4).
func (m *Manager) transport(in store.Integration) (mcp.Transport, error) {
	hc, err := m.upstreamHTTPClient(in)
	if err != nil {
		return nil, err
	}
	switch in.Transport {
	case "streamable-http":
		tr := &mcp.StreamableClientTransport{Endpoint: in.Endpoint, HTTPClient: hc}
		if in.AuthKind == "oauth" && m.OAuthFor != nil {
			h, err := m.OAuthFor(in)
			if err != nil {
				return nil, err
			}
			tr.OAuthHandler = h
		}
		return tr, nil
	case "sse":
		return &mcp.SSEClientTransport{Endpoint: in.Endpoint, HTTPClient: hc}, nil
	case "stdio-supervised":
		// handled in dial: each launch needs a fresh CommandTransport (SPEC §6.2)
		return nil, fmt.Errorf("integrations: stdio-supervised dials through its supervisor")
	default:
		return nil, fmt.Errorf("integrations: unknown transport %q", in.Transport)
	}
}

// upstreamHTTPClient returns the HTTP client for an integration; static auth
// wraps it so the configured header rides every request. Caller identity is
// never consulted here — a caller token cannot reach an upstream (SPEC §6.3).
func (m *Manager) upstreamHTTPClient(in store.Integration) (*http.Client, error) {
	base := m.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	if in.AuthKind != "static" || m.StaticHeader == nil {
		return base, nil
	}
	name, value, err := m.StaticHeader(in)
	if err != nil {
		return nil, err
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	u, err := url.Parse(in.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("integrations: endpoint: %w", err)
	}
	c := *base
	c.Transport = headerRoundTripper{next: rt, name: name, value: value, host: u.Host}
	return &c, nil
}

// headerRoundTripper attaches the static credential ONLY to requests for the
// integration's own host: a redirect to any other host (each hop re-enters
// RoundTrip) never carries the owner's secret along (SPEC §6.3, §12).
type headerRoundTripper struct {
	next  http.RoundTripper
	name  string
	value string
	host  string
}

func (h headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != h.host {
		return h.next.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set(h.name, h.value)
	return h.next.RoundTrip(r)
}

// isAuthError classifies an upstream failure as an authorization failure
// (SPEC §6.3): the SDK's OAuth sentinel, oauth2's token-endpoint error, or a
// 401/403-shaped message. Heuristic on purpose — the transports wrap errors
// as text — and only consulted for auth=oauth integrations.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, auth.ErrOAuth) || errors.Is(err, auth.ErrInvalidToken) {
		return true
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"401", "403", "unauthorized", "forbidden", "invalid_grant", "authoriz", "oauth"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// NoteCallFailure records what a real call learned about this upstream. A
// server can accept the handshake and answer tools/list without a credential
// and still refuse every actual call — Google's Calendar MCP does exactly that
// — so connect succeeded, the catalog snapshot succeeded, and the row sat green
// while nothing worked. Only an authentication failure moves the row: a
// transient network error is the health cycle's business, and flapping the
// status on one bad call would be worse than saying nothing.
func (m *Manager) NoteCallFailure(ctx context.Context, integrationID string, err error) {
	if err == nil || !isAuthError(err) {
		return
	}
	in, gerr := m.Store.GetIntegrationByID(ctx, integrationID)
	if gerr != nil {
		return
	}
	status := m.failStatus(in, err)
	if in.Status == status {
		return
	}
	_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, status)
	m.audit("integration_call", "account:"+in.AccountID+" integration:"+in.Slug, status)
}

// failStatus picks the status a dial/health failure lands in (SPEC §6.3/§6.10).
func (m *Manager) failStatus(in store.Integration, err error) string {
	// An upstream answering 401/403 is an authentication problem no matter what
	// this row was configured with. Filing it under "unreachable" for an
	// `auth: none` row sent the owner looking for a network fault while the
	// server was asking, in its WWW-Authenticate header, to be signed into.
	if isAuthError(err) {
		m.audit("integration_auth", "account:"+in.AccountID+" integration:"+in.Slug, "error")
		if m.OnAuthError != nil {
			m.OnAuthError(in.ID)
		}
		return "auth_error"
	}
	return "unreachable"
}

func (m *Manager) dial(ctx context.Context, in store.Integration) (*mcp.ClientSession, error) {
	if in.Transport == "stdio-supervised" {
		return m.dialStdio(ctx, in)
	}
	tr, err := m.transport(in)
	if err != nil {
		return nil, err
	}
	return m.newClient(in).Connect(ctx, tr, nil)
}

func (m *Manager) newClient(in store.Integration) *mcp.Client {
	var opts *mcp.ClientOptions
	if m.OnToolListChanged != nil {
		id := in.ID
		opts = &mcp.ClientOptions{
			ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
				m.OnToolListChanged(id)
			},
		}
	}
	return mcp.NewClient(&mcp.Implementation{Name: "pact-gateway", Version: "1"}, opts)
}

// StdioSupervisor returns (creating if needed) the restart supervisor for a
// stdio integration, refreshing its config from the row.
func (m *Manager) StdioSupervisor(in store.Integration) *Supervisor {
	cfg := StdioConfig{Command: in.Command}
	if m.StdioConfigFor != nil {
		cfg = m.StdioConfigFor(in)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stdio == nil {
		m.stdio = map[string]*Supervisor{}
	}
	sup := m.stdio[in.ID]
	if sup == nil {
		sup = &Supervisor{Sleep: m.StdioSleep}
		m.stdio[in.ID] = sup
	}
	sup.SetConfig(cfg)
	return sup
}

// dialStdio launches the child under supervision (SPEC §6.2): backoff pacing and
// give-up live in the supervisor; a fresh process is spawned per attempt, so the
// health cycle's redial path doubles as the restart path.
func (m *Manager) dialStdio(ctx context.Context, in store.Integration) (*mcp.ClientSession, error) {
	sup := m.StdioSupervisor(in)
	if err := sup.Gate(); err != nil {
		return nil, err
	}
	cmd, err := sup.BuildCmd()
	if err != nil {
		return nil, err
	}
	cs, err := m.newClient(in).Connect(ctx, &mcp.CommandTransport{
		Command: cmd, TerminateDuration: sup.config().TerminateDuration,
	}, nil)
	if err != nil {
		sup.NoteFailure()
		m.audit("integration_child_crash", "account:"+in.AccountID+" integration:"+in.Slug, "error")
		return nil, err
	}
	sup.NoteSuccess()
	return cs, nil
}

// pingEvery resolves the cycle interval: 0 → SPEC §6.10 default; <0 → off.
func (m *Manager) pingEvery() time.Duration {
	switch {
	case m.PingEvery < 0:
		return 0
	case m.PingEvery == 0:
		return DefaultPingEvery
	}
	return m.PingEvery
}

// startLoop (re)starts the single health cycle for an integration.
func (m *Manager) startLoop(integrationID string) {
	every := m.pingEvery()
	if every <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	if m.loops == nil {
		m.loops = map[string]context.CancelFunc{}
	}
	if old := m.loops[integrationID]; old != nil {
		old()
	}
	m.loops[integrationID] = cancel
	m.mu.Unlock()
	go m.loop(ctx, integrationID, every)
}

func (m *Manager) stopLoop(integrationID string) {
	m.mu.Lock()
	cancel := m.loops[integrationID]
	delete(m.loops, integrationID)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// install registers a fresh session as THE conn for the integration, closing
// any previous one, and returns the conn.
func (m *Manager) install(integrationID string, session *mcp.ClientSession) *conn {
	m.mu.Lock()
	if m.conns == nil {
		m.conns = map[string]*conn{}
	}
	old := m.conns[integrationID]
	c := &conn{session: session}
	m.conns[integrationID] = c
	m.mu.Unlock()
	if old != nil {
		_ = old.session.Close()
	}
	return c
}

// Connect dials the integration and moves it to `ok` (SPEC §6.3); OnConnected
// then takes the first catalog snapshot. A failed dial still arms the health
// cycle so the node keeps retrying (SPEC §6.10) instead of staying dead.
func (m *Manager) Connect(ctx context.Context, integrationID string) error {
	in, err := m.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return err
	}
	_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, "connecting")
	session, err := m.dial(ctx, in)
	if err != nil {
		_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, m.failStatus(in, err))
		m.audit("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "error")
		m.startLoop(in.ID)
		return fmt.Errorf("integrations: connect %s: %w", in.Slug, err)
	}
	m.install(in.ID, session)
	if err := m.Store.UpdateIntegrationStatus(ctx, in.ID, "ok"); err != nil {
		return err
	}
	m.audit("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
	m.startLoop(in.ID)
	if m.OnConnected != nil {
		m.OnConnected(in.ID)
	}
	return nil
}

// Reconnect is the OWNER's connect: the portal's Connect/Reconnect button. It is Connect after
// clearing a supervised child's give-up (SPEC §6.2). Left alone, a child that exhausted its
// restarts stays given up until its failure window has passed, and the health cycle's next redial
// launches it then; the owner asking is the one thing that ends give-up at once. Startup and the
// health cycle call Connect and never this. Until 2026-09-24 the button called Connect, whose Gate
// refused a given-up child inside the window, so "reconnect to retry" retried nothing (review
// N-15: Supervisor.Reset had no production caller).
func (m *Manager) Reconnect(ctx context.Context, integrationID string) error {
	m.mu.Lock()
	sup := m.stdio[integrationID]
	m.mu.Unlock()
	if sup != nil {
		sup.Reset()
	}
	return m.Connect(ctx, integrationID)
}

// Disconnect stops the cycle, closes the session, and disables the integration.
func (m *Manager) Disconnect(ctx context.Context, integrationID string) error {
	in, err := m.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return err
	}
	m.stopLoop(in.ID)
	m.mu.Lock()
	c := m.conns[in.ID]
	delete(m.conns, in.ID)
	m.mu.Unlock()
	if c != nil {
		_ = c.session.Close()
	}
	if err := m.Store.UpdateIntegrationStatus(ctx, in.ID, "disabled"); err != nil {
		return err
	}
	m.audit("integration_disconnect", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
	return nil
}

// Available reports whether the integration's tools may run right now: connected
// and not mid-outage. Unavailable tools fail with `unavailable` (SPEC §6.10).
func (m *Manager) Available(integrationID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.conns[integrationID]
	return c != nil && c.failures == 0
}

// Withheld reports whether the integration's tools are hidden from tools/list.
func (m *Manager) Withheld(integrationID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.conns[integrationID]
	return c != nil && c.withheld
}

// Session hands the live session to the serving modes (passthrough etc.).
func (m *Manager) Session(integrationID string) *mcp.ClientSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.conns[integrationID]; c != nil {
		return c.session
	}
	return nil
}

// HealthCheck runs one health cycle (SPEC §6.10): ping; on failure — or when
// no session exists at all (a failed initial connect) — try a fresh dial;
// count consecutive failures; withhold past the threshold; on success restore,
// re-announce, and refresh (OnConnected on recovery, OnHealthy every cycle).
func (m *Manager) HealthCheck(ctx context.Context, integrationID string) error {
	in, err := m.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return err
	}
	m.mu.Lock()
	c := m.conns[in.ID]
	m.mu.Unlock()
	if c == nil {
		// nothing connected: the cycle IS the retry path
		session, dialErr := m.dial(ctx, in)
		if dialErr != nil {
			_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, m.failStatus(in, dialErr))
			m.audit("integration_health", "account:"+in.AccountID+" integration:"+in.Slug, "error")
			return fmt.Errorf("integrations: %s still unreachable: %w", in.Slug, dialErr)
		}
		m.mu.Lock()
		if m.conns == nil {
			m.conns = map[string]*conn{}
		}
		if m.conns[in.ID] != nil {
			// a concurrent Connect won: keep theirs, drop ours
			m.mu.Unlock()
			_ = session.Close()
			return nil
		}
		c = &conn{session: session}
		m.conns[in.ID] = c
		m.mu.Unlock()
		_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, "ok")
		m.audit("integration_recover", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
		if m.OnConnected != nil {
			m.OnConnected(in.ID)
		}
		if m.OnHealthy != nil {
			m.OnHealthy(in.ID)
		}
		return nil
	}
	if err := c.session.Ping(ctx, nil); err != nil {
		// The session may be dead rather than the upstream: try a fresh dial.
		fresh, dialErr := m.dial(ctx, in)
		if dialErr != nil {
			return m.healthFail(ctx, in, c, dialErr)
		}
		m.mu.Lock()
		if m.conns[in.ID] != c {
			// replaced (Connect) or removed (Disconnect) while we dialed:
			// the fresh session has no owner — never orphan it
			m.mu.Unlock()
			_ = fresh.Close()
			return nil
		}
		old := c.session
		c.session = fresh
		m.mu.Unlock()
		_ = old.Close()
		return m.healthOK(ctx, in, c, true)
	}
	return m.healthOK(ctx, in, c, false)
}

func (m *Manager) healthOK(ctx context.Context, in store.Integration, c *conn, redialed bool) error {
	m.mu.Lock()
	wasOut := c.failures > 0
	wasWithheld := c.withheld
	c.failures = 0
	c.withheld = false
	m.mu.Unlock()
	if wasOut {
		_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, "ok")
		m.audit("integration_recover", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
	}
	if wasWithheld {
		m.audit("integration_restore", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
		if m.OnAvailability != nil {
			m.OnAvailability(in.ID, false)
		}
	}
	if (wasOut || redialed) && m.OnConnected != nil {
		m.OnConnected(in.ID)
	}
	if m.OnHealthy != nil {
		m.OnHealthy(in.ID)
	}
	return nil
}

func (m *Manager) healthFail(ctx context.Context, in store.Integration, c *conn, cause error) error {
	m.mu.Lock()
	c.failures++
	failures := c.failures
	trip := failures >= m.withholdAfter() && !c.withheld
	if trip {
		c.withheld = true
	}
	m.mu.Unlock()
	if failures == 1 {
		_ = m.Store.UpdateIntegrationStatus(ctx, in.ID, m.failStatus(in, cause))
	}
	m.audit("integration_health", "account:"+in.AccountID+" integration:"+in.Slug, "error")
	if trip {
		m.audit("integration_withhold", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
		if m.OnAvailability != nil {
			m.OnAvailability(in.ID, true)
		}
	}
	return fmt.Errorf("integrations: %s unreachable (%d consecutive failures)", in.Slug, failures)
}

func (m *Manager) loop(ctx context.Context, integrationID string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.HealthCheck(ctx, integrationID)
		}
	}
}
