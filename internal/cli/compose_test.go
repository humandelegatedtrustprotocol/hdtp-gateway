package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
)

// freePort reserves and releases a port, so the config can name it.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

type running struct {
	t        *testing.T
	dir      string
	internal string
	public   string
	out      *bytes.Buffer
	cancel   context.CancelFunc
	done     chan int
	once     sync.Once
	code     int
}

// stop ends the node and waits for serve to return. It is idempotent: a test
// that stops the node itself (to check something across a restart) and the
// cleanup that always runs must not both wait on a channel only one can drain.
func (r *running) stop() int {
	r.once.Do(func() {
		r.cancel()
		select {
		case r.code = <-r.done:
		case <-time.After(20 * time.Second):
			r.t.Error("serve did not return after its context ended")
		}
	})
	return r.code
}

// runServe starts the real `serve` command against a fresh data dir.
func runServe(t *testing.T, seed func(t *testing.T, dir string)) *running {
	t.Helper()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	cfg := map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "store_engine": "sqlite",
		"seal": "optional", "client_cert": "preferred",
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if seed != nil {
		seed(t, dir)
	}
	return startServeAt(t, dir, cfgPath, internal, public)
}

// startServeAt runs `serve` against an existing config and waits for its portal.
func startServeAt(t *testing.T, dir, cfgPath, internal, public string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{t: t, dir: dir, internal: internal, public: public,
		out: &bytes.Buffer{}, cancel: cancel, done: make(chan int, 1)}
	var mu sync.Mutex
	out := &lockedBuf{buf: r.out, mu: &mu}
	go func() { r.done <- serveWith(ctx, []string{"--config", cfgPath}, out, out) }()
	t.Cleanup(func() { r.stop() })
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get("http://" + internal + "/healthz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return r
			}
		}
		select {
		case code := <-r.done:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("serve exited with %d: %s", code, r.out.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("portal never came up: %s", r.out.String())
	return nil
}

type lockedBuf struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// openStoreAt opens the served database directly, the way the admin CLI would.
func openStoreAt(t *testing.T, dir string) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// AC (P6-03): the shipped binary serves all four surfaces — portal, public MCP,
// invite landing, owner MCP — and shuts down cleanly.
func TestServeRunsTheWholeNode(t *testing.T) {
	ctx := context.Background()
	var acct store.Account
	r := runServe(t, func(t *testing.T, dir string) {
		// an account and an owner token exist before the node starts
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		acct, err = idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		acct = issueLeafFor(t, idm, acct, configPublicURL(t, dir))
	})

	// 1. the portal answers on the internal bind
	if code := getStatus(t, "http://"+r.internal+"/"); code != 200 {
		t.Fatalf("portal: %d", code)
	}

	// 2. the PUBLIC surface completes a TLS handshake and lists guest tools.
	// The peer presents a CHAIN — leaf then root — because that is what proves an
	// identity now; a single self-signed certificate proves nothing (PACT §14.2
	// rule 1) and its bearer would be refused identity_required.
	tp := newTestPeer(t, "Peer", "https://peer.example/a/p/mcp")
	client := &outbound.Client{Keypair: tp.KP, Cert: tp.Cert}
	peer := outbound.Peer{Endpoint: "https://" + r.public + "/a/alice/mcp", Fingerprint: acct.Fingerprint}
	hc, err := client.HTTPClient(peer)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "peer", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: peer.Endpoint, HTTPClient: hc}, nil)
	if err != nil {
		t.Fatalf("public connect: %v", err)
	}
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("public tools/list: %v", err)
	}
	cs.Close()
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if !names["redeem_invite"] || !names["request_contact"] {
		t.Fatalf("guest surface from the real binary: %v", names)
	}

	// 3. an issued invite renders on the public listener
	st := openStoreAt(t, r.dir)
	cm := &contacts.Manager{Store: st}
	token, _, err := cm.CreateInvite(ctx, acct.ID, contacts.InviteOptions{MaxUses: 1, Preset: "friend", AutoAccept: true})
	if err != nil {
		t.Fatal(err)
	}
	body := getBody(t, insecureGet(t, "https://"+r.public+"/i/"+token))
	if !strings.Contains(body, "X-PACT-CERT") {
		t.Fatalf("landing page: %s", firstLine(body))
	}

	// 4. and redeeming it over the public surface really pairs
	peerCard := tp.Card("Peer")
	res, err := client.CallTool(ctx, peer, "redeem_invite",
		map[string]any{"token": token, "card": peerCard}, outbound.CallOptions{Plaintext: true})
	if err != nil || res.IsError {
		t.Fatalf("redeem over the real binary: %v %+v", err, res)
	}
	c, err := st.GetContact(ctx, acct.ID, tp.Root())
	if err != nil || c.Status != "active" {
		t.Fatalf("pairing did not persist: %+v %v", c, err)
	}
}

// AC (P6-03): the owner MCP refuses an unknown bearer and accepts a valid one.
func TestServeOwnerMCPBearerGate(t *testing.T) {
	ctx := context.Background()
	var token string
	r := runServe(t, func(t *testing.T, dir string) {
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		a, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		a = issueLeafFor(t, idm, a, configPublicURL(t, dir))
		owner, err := st.CreateOwnerWithID(ctx, "", "Owner")
		if err != nil {
			t.Fatal(err)
		}
		tok := &auth.TokenService{Store: st}
		token, _, err = tok.Create(ctx, owner.ID, "agent", a.ID)
		if err != nil {
			t.Fatal(err)
		}
	})

	url := "http://" + r.internal + "/owner/mcp"
	// no token, and a wrong one: both refused, neither reaches a tool
	for _, bearer := range []string{"", "Bearer not-a-real-token"} {
		if _, err := dialOwnerMCP(ctx, url, bearer); err == nil {
			t.Fatalf("owner MCP accepted %q", bearer)
		}
	}
	cs, err := dialOwnerMCP(ctx, url, "Bearer "+token)
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("owner MCP exposed no tools")
	}
}

/* -------------------------------- helpers ------------------------------- */

type bearerRT struct {
	base   http.RoundTripper
	bearer string
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.bearer != "" {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", b.bearer)
	}
	return b.base.RoundTrip(r)
}

func dialOwnerMCP(ctx context.Context, url, bearer string) (*mcp.ClientSession, error) {
	c := mcp.NewClient(&mcp.Implementation{Name: "owner-agent", Version: "1"}, nil)
	tr := &mcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: bearerRT{http.DefaultTransport, bearer}},
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Connect(dialCtx, tr, nil)
}

// openKeyringAt opens the same keyring file `serve` will use.
func openKeyringAt(t *testing.T, dir string) *core.Keyring {
	t.Helper()
	kr, err := core.OpenKeyring(filepath.Join(dir, "keyring.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func insecureGet(t *testing.T, url string) *http.Response {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return res
}

func getBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status %d: %s", res.StatusCode, firstLine(string(b)))
	}
	return string(b)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// AC (P6-03): ending the serving context returns 0 and releases the data-dir
// lock, so the node can be restarted (or an offline CLI command can run).
func TestServeShutsDownAndReleasesTheLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	cfg, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "store_engine": "sqlite",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	created, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	issueLeafFor(t, idm, created, configPublicURL(t, dir))
	st.Close()

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	var mu sync.Mutex
	out := &lockedBuf{buf: &bytes.Buffer{}, mu: &mu}
	go func() { done <- serveWith(runCtx, []string{"--config", cfgPath}, out, out) }()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if res, err := http.Get("http://" + internal + "/healthz"); err == nil {
			res.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// while it serves, the lock is held
	if _, err := core.AcquireLock(dir); err == nil {
		t.Fatal("the data-dir lock was free while serving")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("serve exited %d: %s", code, out.buf.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not return after its context ended")
	}
	lock, err := core.AcquireLock(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	lock.Release()
	// and the public port is free again
	ln, err := net.Listen("tcp", public)
	if err != nil {
		t.Fatalf("public port still held: %v", err)
	}
	ln.Close()
}

// AC (P10-08b): the owner MCP requires a token on every bind, loopback included
// (SPEC §8.3, §8.4 as amended by escalation E6).
//
// The spec said loopback "additionally accepts unauthenticated sessions" and the
// code required a token always. The code was right and the spec was amended:
// the portal is a browser surface a person sits at, the owner MCP is a
// programmatic one, and granting full owner authority to anything that can open
// a loopback socket hands it to every other process on the host.
func TestOwnerMCPRequiresATokenEvenOnLoopback(t *testing.T) {
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)

	// A loopback caller with no Authorization header must be refused.
	res, err := http.Post("http://"+r.internal+"/owner/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("the owner MCP served an unauthenticated loopback session")
	}
}

// AC (P11-11): revoking an owner-MCP token ends an ESTABLISHED session, and a
// session id alone is not authority.
//
// The bearer check ran only inside the SDK's getServer callback, which fires
// solely for a request carrying no session id — so an established session was
// never re-checked. SPEC §3.4 says revocation "takes effect immediately"; it did
// not, and anyone holding the session id could drive the owner MCP with no
// Authorization header at all. That endpoint is mounted outside the portal's
// session and CSRF layers, so the bearer check is the only gate there is.
func TestOwnerMCPRevocationEndsALiveSession(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	st0 := migrated(t, dir)
	o, err := st0.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := st0.AddMembership(ctx, o.ID, acct.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	st0.Close()
	r := startServeAt(t, dir, cfgPath, internal, public)
	token := mintOwnerToken(t, dir, r)

	post := func(bearer, sid, payload string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", "http://"+r.internal+"/owner/mcp", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"a","version":"1"}}}`

	res := post(token, "", initialize)
	sid := res.Header.Get("Mcp-Session-Id")
	res.Body.Close()
	if sid == "" {
		t.Fatalf("no owner-MCP session was established (%d)", res.StatusCode)
	}

	// The session id without a token is not authority.
	res2 := post("", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	defer res2.Body.Close()
	if res2.StatusCode == http.StatusOK {
		t.Fatal("an established owner-MCP session was driven with no Authorization header")
	}

	// Revoke, then use the SAME live session: it must stop working at once.
	p := newPortal(t, "http://"+r.internal)
	st := openStoreAt(t, dir)
	toks, err := st.ListTokens(ctx)
	if err != nil || len(toks) == 0 {
		t.Fatalf("no token rows: %v", err)
	}
	p.post("/owners/tokens/"+toks[0].ID+"/revoke", url.Values{})
	res3 := post(token, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	defer res3.Body.Close()
	if res3.StatusCode == http.StatusOK {
		t.Fatal("a revoked token kept driving its established session")
	}
}
