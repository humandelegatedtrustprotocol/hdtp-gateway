// Package multiprocess proves the node's horizontal scaling end to end (docs/release/
// mcp-stateless-2026-09-28.md, N7): two `pact-gateway serve` processes of the shipped binary,
// sharing one store, behind a round-robin proxy — once on one SQLite data dir, once on one
// Postgres database with a data dir each. Hermetic: no Docker, no network beyond loopback. The
// Postgres half runs where PACT_TEST_POSTGRES_DSN names a server (the pre-push hook starts one),
// and says it skipped where none is.
package multiprocess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"

	"github.com/pact-cloud/pact-gateway/harness/owner"
	"github.com/pact-cloud/pact-gateway/harness/peer"
	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// publicURL is the address the node advertises; the proxy is where it really listens.
const publicURL = "https://node.test"

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary builds the shipped `pact-gateway` once for the package.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pact-n7-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "pact-gateway")
		// Built in the node's own module (the repository root), with its go.sum: the harness
		// module requires the node only for the packages it imports.
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/pact-gateway")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("building pact-gateway: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// deployment is one engine's shape: where each process keeps its data, and what it is told of
// the store.
type deployment struct {
	engine string
	dsn    string // postgres only
	dirs   [2]string
}

// seeded is what the store holds before either process starts.
type seeded struct {
	accountID, slug string
	leaf            []byte
	root            string
	ownerToken      string
	inviteToken     string
}

// seed writes alice — an account certified by her wallet — her owner and an owner-MCP token, and an
// invite a stranger can redeem, into the store both processes will share.
func seed(t *testing.T, st store.Store, kr *core.Keyring) seeded {
	t.Helper()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: kr}
	a, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alice", Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	csr, err := idm.IssueCSR(ctx, a.ID, identity.PurposeSignup, identity.EndpointFor(publicURL, a.Slug), now)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: "Alice", RootKey: rootKey, RootSPKIs: [][]byte{rootKey.Public.SPKI},
		Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, rootCert}, now); err != nil {
		t.Fatal(err)
	}
	o, err := st.CreateOwnerWithID(ctx, "", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, o.ID, a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	token, _, err := (&auth.TokenService{Store: st}).Create(ctx, o.ID, "n7 agent", "")
	if err != nil {
		t.Fatal(err)
	}
	invite, _, err := (&contacts.Manager{Store: st}).CreateInvite(ctx, a.ID, contacts.InviteOptions{AutoAccept: true, Permissions: []string{"message.text"}})
	if err != nil {
		t.Fatal(err)
	}
	return seeded{accountID: a.ID, slug: a.Slug, leaf: iss.DER,
		root: pactidentity.Fingerprint(rootKey.Public.SPKI), ownerToken: token, inviteToken: invite}
}

// proc is one running `serve`.
type proc struct {
	name             string
	internal, public string
	cfg              string
	cmd              *exec.Cmd
	out              *lockedBuffer
	exited           chan struct{}
	stopped          sync.Once
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func start(t *testing.T, bin, name string, d deployment, i int, env []string) *proc {
	t.Helper()
	p := &proc{name: name, internal: freePort(t), public: freePort(t), out: &lockedBuffer{}, exited: make(chan struct{})}
	cfg := map[string]any{
		"data_dir": d.dirs[i], "internal_bind": p.internal, "public_bind": p.public,
		"public_url": publicURL, "seal": "required", "client_cert": "preferred", "store_engine": d.engine,
	}
	if d.engine == "postgres" {
		cfg["postgres_dsn"] = d.dsn
	}
	b, _ := json.Marshal(cfg)
	p.cfg = filepath.Join(t.TempDir(), name+".json")
	if err := os.WriteFile(p.cfg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	p.cmd = exec.Command(bin, "serve", "--config", p.cfg)
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.exited) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}

// stop ends the process as an operator would, and waits for it.
func (p *proc) stop(t *testing.T) {
	p.stopped.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exited:
		case <-time.After(30 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exited
			t.Errorf("%s did not stop within 30 s:\n%s", p.name, p.out.String())
		}
	})
}

// ready waits until the process's owner MCP answers.
func (p *proc) ready(t *testing.T, token string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("POST", "http://"+p.internal+"/owner/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+token)
		if res, err := http.DefaultClient.Do(req); err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-p.exited:
			t.Fatalf("%s exited:\n%s", p.name, p.out.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("%s never answered:\n%s", p.name, p.out.String())
}

// roundRobin is a TCP proxy that hands each new connection to the next backend in turn: TLS
// passes through it untouched, so each process terminates its own.
type roundRobin struct {
	ln       net.Listener
	backends []string
	next     atomic.Int64
	served   []atomic.Int64
}

func newRoundRobin(t *testing.T, backends ...string) *roundRobin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rr := &roundRobin{ln: ln, backends: backends, served: make([]atomic.Int64, len(backends))}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			i := int(rr.next.Add(1)-1) % len(backends)
			rr.served[i].Add(1)
			wg.Go(func() { pipe(c, backends[i]) })
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return rr
}

func pipe(c net.Conn, to string) {
	defer c.Close()
	b, err := net.Dial("tcp", to)
	if err != nil {
		return
	}
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, b); done <- struct{}{} }()
	<-done
}

// TestTwoNodeProcessesBehindARoundRobinProxy is the plan's N7. On each engine, two processes of
// the shipped binary share one store behind a proxy that alternates connections between them, and:
//   - a stranger's surface each composed as a guest becomes a contact's on both once one of them
//     takes the stranger's redemption (a cross-process invalidation, not a cache that happened to
//     be empty);
//   - a 2026-07-28 client (the node's own outbound client) and a 2025-11-25 client both complete a
//     sealed send_message through the proxy;
//   - the owner's wait_for_updates parked on process B wakes for a message process A took;
//   - one process at a time holds the outbound retries' lease, the same one throughout;
//   - both processes appended to the one audit chain with no failed append, and it verifies.
//
// Reverting N5 — an audit writer that carries the chain's head in memory — makes it fail: the
// processes' appends collide on seq, which each reports as `audit: …` and loses the row.
func TestTwoNodeProcessesBehindARoundRobinProxy(t *testing.T) {
	bin := binary(t)
	t.Run("sqlite", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
		if err != nil {
			t.Fatal(err)
		}
		kr, err := core.OpenKeyring(filepath.Join(dir, "keyring.key"), func(string) (string, bool) { return "", false })
		if err != nil {
			t.Fatal(err)
		}
		s := seed(t, st, kr)
		st.Close()
		scenario(t, bin, deployment{engine: "sqlite", dirs: [2]string{dir, dir}}, s, nil)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("PACT_TEST_POSTGRES_DSN not set: the Postgres half needs a server (the pre-push hook starts one)")
		}
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS pact_n7")
		if _, err := admin.Exec(ctx, "CREATE DATABASE pact_n7"); err != nil {
			t.Fatal(err)
		}
		admin.Close(ctx)
		target := rewriteDB(dsn, "pact_n7")
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		masterKey := base64.StdEncoding.EncodeToString(key)
		st, err := store.OpenPostgres(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "unused.key"), func(k string) (string, bool) {
			return masterKey, k == "PACT_MASTER_KEY"
		})
		if err != nil {
			t.Fatal(err)
		}
		s := seed(t, st, kr)
		st.Close()
		scenario(t, bin, deployment{engine: "postgres", dsn: target, dirs: [2]string{t.TempDir(), t.TempDir()}}, s,
			[]string{"PACT_MASTER_KEY=" + masterKey})
	})
}

func rewriteDB(dsn, db string) string {
	i := strings.LastIndex(dsn, "/")
	rest := dsn[i+1:]
	if j := strings.Index(rest, "?"); j >= 0 {
		return dsn[:i+1] + db + rest[j:]
	}
	return dsn[:i+1] + db
}

func scenario(t *testing.T, bin string, d deployment, s seeded, env []string) {
	ctx := context.Background()
	env = append(env, "PACT_LOG=off")
	a := start(t, bin, "A", d, 0, env)
	a.ready(t, s.ownerToken)
	b := start(t, bin, "B", d, 1, env)
	b.ready(t, s.ownerToken)
	rr := newRoundRobin(t, a.public, b.public)

	bharat, err := peer.NewAgent("bharat")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := identity.EndpointFor(publicURL, s.slug)
	via := func(dial string) peer.Target {
		return peer.Target{Endpoint: endpoint, Dial: dial, Seal: "required", Root: s.root, Leaf: s.leaf}
	}
	proxied := via(rr.ln.Addr().String())

	// 1. A stranger lists the surface through the proxy twice: each process composes it a guest's.
	for i := 0; i < 2; i++ {
		tools, err := bharat.ListTools(ctx, proxied)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(tools, ","), "send_message") {
			t.Fatalf("a stranger was served %v", tools)
		}
	}
	// 2. The stranger redeems the invite (sealed, 2026-07-28) — on whichever process the proxy picks.
	if res, err := bharat.Call(ctx, proxied, "redeem_invite", map[string]any{"token": s.inviteToken, "card": bharat.Card("required")}, "n7-redeem"); err != nil {
		t.Fatalf("redeem: %v %s", err, res)
	}
	// 3. Both processes now serve a contact's surface, the one that composed a guest's included.
	for i := 0; i < 2; i++ {
		var tools []string
		deadline := time.Now().Add(10 * time.Second)
		for {
			if tools, err = bharat.ListTools(ctx, proxied); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(tools, ","), "send_message") || time.Now().After(deadline) {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if !strings.Contains(strings.Join(tools, ","), "send_message") {
			t.Fatalf("a process kept serving the new contact a guest's surface: %v", tools)
		}
	}

	// 4. The owner waits on B; bharat's message goes straight to A; B wakes.
	ownerB, err := owner.Connect(ctx, "http://"+b.internal+"/owner/mcp", s.ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerB.Close()
	first, err := ownerB.Call(ctx, "wait_for_updates", map[string]any{"account_id": s.accountID})
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		Cursor int64 `json:"cursor"`
	}
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatalf("first wait: %v %s", err, first)
	}
	type woke struct {
		text    string
		err     error
		elapsed time.Duration
	}
	wakes := make(chan woke, 1)
	go func() {
		began := time.Now()
		text, err := ownerB.Call(ctx, "wait_for_updates", map[string]any{"account_id": s.accountID, "since": start.Cursor, "timeout_sec": 20})
		wakes <- woke{text, err, time.Since(began)}
	}()
	time.Sleep(time.Second)
	if res, err := bharat.Call(ctx, via(a.public), "send_message", map[string]any{"msg_id": "n7-to-a", "text": "taken by A"}, "n7-to-a"); err != nil {
		t.Fatalf("send to A: %v %s", err, res)
	}
	w := <-wakes
	if w.err != nil || strings.Contains(w.text, `"timed_out":true`) || !strings.Contains(w.text, `"threads":[`) {
		t.Fatalf("the owner's wait on B did not wake for A's message (after %s): %v %s", w.elapsed, w.err, w.text)
	}

	// 5. A 2025-11-25 client completes a sealed send_message through the proxy.
	legacySealedSend(t, bharat, proxied, s)

	// 6. One process holds the retries' lease, the same one throughout.
	holder := func() string {
		t.Helper()
		var h string
		if err := rawQuery(t, d, "SELECT holder FROM leases WHERE name = 'retries'", &h); err != nil {
			return ""
		}
		return h
	}
	var first6 string
	for deadline := time.Now().Add(40 * time.Second); first6 == "" && time.Now().Before(deadline); time.Sleep(time.Second) {
		first6 = holder()
	}
	pids := []string{fmt.Sprintf("/%d/", a.cmd.Process.Pid), fmt.Sprintf("/%d/", b.cmd.Process.Pid)}
	if first6 == "" || (!strings.Contains(first6, pids[0]) && !strings.Contains(first6, pids[1])) {
		t.Fatalf("no process of the two holds the retries' lease: %q", first6)
	}
	time.Sleep(20 * time.Second) // more than a sweep: both processes have tried the lease since
	if again := holder(); again != first6 {
		t.Fatalf("the retries' lease moved from %q to %q while both processes ran", first6, again)
	}

	// Both processes served connections.
	for i, name := range []string{"A", "B"} {
		if rr.served[i].Load() == 0 {
			t.Fatalf("the proxy never sent a connection to %s", name)
		}
	}

	// 7. Stop both. Neither failed an audit append, both wrote to the one chain, and it verifies.
	a.stop(t)
	b.stop(t)
	for _, p := range []*proc{a, b} {
		if strings.Contains(p.out.String(), "audit: ") {
			t.Fatalf("%s failed an audit append:\n%s", p.name, p.out.String())
		}
	}
	var started int
	if err := rawQuery(t, d, "SELECT COUNT(*) FROM audit_events WHERE action = 'public_listener' AND outcome = 'started'", &started); err != nil || started != 2 {
		t.Fatalf("the chain holds %d public_listener rows from two processes: %v", started, err)
	}
	verify := exec.Command(bin, "audit", "verify", "--config", a.cfg)
	verify.Env = append(os.Environ(), env...)
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("audit verify: %v\n%s", err, out)
	}
}

// rawQuery reads one value from the shared store: a test may write SQL.
func rawQuery(t *testing.T, d deployment, q string, into any) error {
	t.Helper()
	var db *sql.DB
	var err error
	if d.engine == "postgres" {
		db, err = sql.Open("pgx", d.dsn)
	} else {
		db, err = sql.Open("sqlite", "file:"+filepath.Join(d.dirs[0], "pact.db")+"?_pragma=busy_timeout(5000)")
	}
	if err != nil {
		return err
	}
	defer db.Close()
	return db.QueryRow(q).Scan(into)
}

// legacySealedSend seals a send_message by hand and sends it over a client of the handshake
// revisions (2025-11-25), then opens the sealed answer.
func legacySealedSend(t *testing.T, a *peer.Agent, target peer.Target, s seeded) {
	t.Helper()
	ctx := context.Background()
	hc, err := a.Client.HTTPClient(target.Peer())
	if err != nil {
		t.Fatal(err)
	}
	// The proxy's address is where the endpoint's name goes; the agent's resolver knows it
	// from its earlier calls.
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "legacy", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: target.Endpoint, HTTPClient: hc},
		&mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if v := cs.InitializeResult().ProtocolVersion; v != "2025-11-25" {
		t.Fatalf("the legacy client negotiated %q", v)
	}
	sender, err := identity.ToLib(a.Keypair)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(s.leaf)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := pactidentity.ParseSPKI(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	env, err := pactidentity.SealRequest(pactidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: "chain", SenderChain: [][]byte{a.Keypair.Leaf, a.Keypair.Root},
		Method: "tools/call", Params: json.RawMessage(`{"name":"send_message","arguments":{"msg_id":"n7-legacy","text":"over 2025-11-25"}}`),
		MsgID: "n7-legacy", TS: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "sealed_call",
		Arguments: map[string]any{"protected": env.Protected, "enc": env.Enc, "ct": env.Ct, "sig": env.Sig}})
	if err != nil || res.IsError {
		t.Fatalf("sealed_call over 2025-11-25: %v %+v", err, res)
	}
	var answer pactidentity.Envelope
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &answer); err != nil {
		t.Fatal(err)
	}
	opened, err := pactidentity.OpenResult(answer, pactidentity.OpenOpts{
		Recipient: sender, MsgID: "n7-legacy", Now: now,
		Pins:         []pactidentity.Pin{{Root: s.root, Endpoint: target.Endpoint, Leaf: pactidentity.B64url(s.leaf), State: "active"}},
		ExpectedRoot: s.root, ExpectedEndpoint: target.Endpoint,
	})
	if err != nil || opened.Error != nil {
		t.Fatalf("the legacy client's sealed answer did not open as a result: %v %s", err, opened.Error)
	}
}
