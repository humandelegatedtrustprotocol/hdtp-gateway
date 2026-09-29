// Package integrationtest holds cross-package scenario tests: the phase exit
// demos of PLAN.md, run against real stores and real HTTP.
package integrationtest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/internalui"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	"github.com/pact-cloud/pact-gateway/internal/internalui/ownermcp"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// P2 exit (PLAN P2-10): full pairing via portal HTTP — wizard gate → account →
// invite created in the invites UI → second node redeems (approval flow, not
// auto-accept) → approval UI activates the contact → a fake owner-agent MCP
// client reads the inbox and answers. Runs on both store engines.
func TestP2ExitPortalPairing(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		runPortalPairing(t, func(name string) store.Store { return openSQLite(t, name) })
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("PACT_TEST_POSTGRES_DSN not set")
		}
		runPortalPairing(t, func(name string) store.Store { return openPostgres(t, dsn, name) })
	})
}

type node struct {
	root     string
	leafDER  []byte
	endpoint string
	st       store.Store
	acct     store.Account
	kp       *identity.Keypair
	spki     []byte
	card     string
	msg      *messaging.Service
	bus      *messaging.Bus
	cm       *contacts.Manager
	owner    store.Owner
}

// newNode migrates a store and provisions one account with a real keypair,
// exactly what `account create` + key issuance produce.
func newNode(t *testing.T, st store.Store, slug, fn string) *node {
	t.Helper()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := st.CreateOwnerWithID(ctx, "", fn)
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: slug, DisplayName: fn, Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, o.ID, a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, a.ID, kp.Fingerprint, []byte{1}); err != nil {
		t.Fatal(err)
	}
	a, _ = st.GetAccountByID(ctx, a.ID)
	spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	// A leaf over the key this account actually holds, so the card it shows and the
	// identity it proves are the same thing. `testid.CardFor` would have produced a
	// valid card belonging to nobody here.
	w := testid.NewWallet(t, fn)
	endpoint := "https://" + slug + ".example/a/" + slug + "/mcp"
	h := w.IssueOver(t, endpoint, spki)
	card, err := contacts.BuildCard(fn, h.LeafDER, "")
	if err != nil {
		t.Fatal(err)
	}
	bus := messaging.NewBus(st)
	return &node{
		st: st, acct: a, kp: kp, spki: spki, card: card,
		root: w.Fpr, leafDER: h.LeafDER, endpoint: endpoint,
		msg: &messaging.Service{Store: st, Bus: bus}, bus: bus,
		// Every request is admitted: the pending cap is not what this scenario is about, and the
		// node's own manager asks the sidecar for it (TestAStrangersRequestIsHeldToTheSidecarsPendingCap).
		cm: &contacts.Manager{Store: st, AdmitRequest: func(context.Context, string, int64) error { return nil }}, owner: o,
	}
}

// portal spins the node's REAL internal handler — wizard gate, CSRF wrap, and all
// page mounts — on 127.0.0.1, plus a browser-like client with a cookie jar.
func portal(t *testing.T, n *node) (*httptest.Server, *http.Client) {
	t.Helper()
	h := internalui.HandlerWithAuth(n.st, internalui.NewSetupTokens(), nil,
		func(mux *http.ServeMux) {
			internalui.MountManagePages(mux, internalui.ManageDeps{
				Store: n.st, Contacts: n.cm, Audit: func(_, _, _ string) {},
				PublicURL: func() string { return "https://pact.example" },
				SignCard:  func(_, _ string) (string, error) { return "c2ln", nil },
			})
		},
		func(mux *http.ServeMux) {
			internalui.MountInboxPages(mux, internalui.InboxDeps{Store: n.st, Msg: n.msg, Bus: n.bus})
		},
		func(mux *http.ServeMux) { internalui.MountAuditPages(mux, n.st) },
	)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return srv, client
}

func csrfOf(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "pact_csrf" {
			return c.Value
		}
	}
	t.Fatal("no pact_csrf cookie after GET")
	return ""
}

func get(t *testing.T, client *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func post(t *testing.T, client *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func runPortalPairing(t *testing.T, open func(name string) store.Store) {
	ctx := context.Background()
	alice := newNode(t, open("alice"), "alice", "Alice")
	bella := newNode(t, open("bella"), "bella", "Bella")
	srvA, clientA := portal(t, alice)

	// 1. Wizard: reachable from loopback while zero passkeys exist. The page is
	// the SPA shell; the §8.6 gate decides whether it serves at all.
	if code, body := get(t, clientA, srvA.URL+"/setup"); code != 200 || !strings.Contains(body, "/assets/") {
		t.Fatalf("wizard: %d\n%s", code, body)
	}

	// 2. Invites UI: create a one-time, approval-required invite.
	if code, _ := get(t, clientA, srvA.URL+"/invites?account="+alice.acct.ID); code != 200 {
		t.Fatalf("invites page: %d", code)
	}
	csrf := csrfOf(t, clientA, srvA.URL)
	resp := post(t, clientA, srvA.URL+"/invites/create?account="+alice.acct.ID, url.Values{
		"csrf": {csrf}, "label": {"for bella"}, "max_uses": {"1"}, "preset": {"basic"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("invite create: %d", resp.StatusCode)
	}
	m := regexp.MustCompile(`[?&]new=([A-Za-z0-9_-]+)`).FindStringSubmatch(resp.Header.Get("Location"))
	if m == nil {
		t.Fatalf("no token in redirect: %s", resp.Header.Get("Location"))
	}
	token := m[1]

	// 3. The invite landing page serves Alice's signed card BEFORE redemption.
	landingMux := http.NewServeMux()
	landingMux.Handle("/i/{token}", internalui.LandingHandler(internalui.LandingDeps{
		Store: alice.st,
		SignCard: func(accountID string) (string, string, error) {
			return alice.card, "c2ln", nil
		},
	}))
	landing := httptest.NewServer(landingMux)
	t.Cleanup(landing.Close)
	lresp, err := http.Get(landing.URL + "/i/" + token)
	if err != nil {
		t.Fatal(err)
	}
	lbody, _ := io.ReadAll(lresp.Body)
	lresp.Body.Close()
	if lresp.StatusCode != 200 || !strings.Contains(string(lbody), "X-PACT-CERT:") {
		t.Fatalf("landing page: %d\n%s", lresp.StatusCode, lbody)
	}

	// 4. Bella redeems with her proven identity → pending (no auto-accept)…
	res, err := alice.cm.RedeemAs(ctx, alice.acct.ID, token, bella.card, contacts.Proof{Fingerprint: bella.root, SPKI: bella.spki, Leaf: bella.leafDER, Endpoint: bella.endpoint})
	if err != nil || res.Status != "pending" {
		t.Fatalf("redeem: %+v %v", res, err)
	}
	// …and pins Alice's card from the landing page on her own node.
	aliceSPKI, _ := x509.MarshalPKIXPublicKey(alice.kp.Signer.Public())
	if _, err := bella.st.InsertContact(ctx, store.Contact{
		AccountID: bella.acct.ID, Fingerprint: alice.root, SPKI: aliceSPKI,
		Status: "active", DisplayName: "Alice", Card: alice.card, PinnedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if c, err := bella.st.GetContact(ctx, bella.acct.ID, alice.root); err != nil || !strings.Contains(c.Card, "X-PACT-CERT:") {
		t.Fatalf("alice not in bella's contacts: %+v %v", c, err)
	}

	// 5. Approval UI: Bella shows up pending; approving activates with the preset.
	if code, body := get(t, clientA, srvA.URL+"/api/requests?account="+alice.acct.ID); code != 200 || !strings.Contains(body, bella.root) {
		t.Fatalf("requests payload misses bella: %d\n%s", code, body)
	}
	resp = post(t, clientA, srvA.URL+"/requests/"+bella.root+"/approve?account="+alice.acct.ID,
		url.Values{"csrf": {csrf}, "preset": {"friend"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("approve: %d", resp.StatusCode)
	}
	c, err := alice.st.GetContact(ctx, alice.acct.ID, bella.root)
	if err != nil || c.Status != "active" || c.Preset != "friend" {
		t.Fatalf("approved contact: %+v %v", c, err)
	}

	// 6. Fake owner-agent connects over MCP and starts waiting: its first wait hands back a cursor.
	agentCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := ownermcp.NewServerWithExtra(ownermcp.Deps{
		Store: alice.st, Msg: alice.msg, Bus: alice.bus, Contacts: alice.cm,
	}, ownermcp.Extra{}, auth.Identity{OwnerID: alice.owner.ID})
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(agentCtx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "owner-agent", Version: "0"}, nil).Connect(agentCtx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	var start struct {
		Cursor int64 `json:"cursor"`
	}
	if err := json.Unmarshal([]byte(callTool(t, cs, "wait_for_updates", map[string]any{"account_id": alice.acct.ID})), &start); err != nil {
		t.Fatalf("first wait: %v", err)
	}

	// 7. Bella's message lands while the agent waits → the wait answers with it; the agent reads
	// and answers.
	woke := make(chan string, 1)
	go func() {
		res, err := cs.CallTool(agentCtx, &mcp.CallToolParams{Name: "wait_for_updates",
			Arguments: map[string]any{"account_id": alice.acct.ID, "since": start.Cursor, "timeout_sec": 25}})
		if err != nil || len(res.Content) == 0 {
			woke <- ""
			return
		}
		woke <- res.Content[0].(*mcp.TextContent).Text
	}()
	if _, err := alice.msg.Record(ctx, alice.acct.ID, bella.kp.Fingerprint, messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "b1", Text: "hi alice, dinner friday?", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	if got := <-woke; !strings.Contains(got, `"threads"`) || strings.Contains(got, `"timed_out":true`) {
		t.Fatalf("the agent's wait did not answer with the new message: %s", got)
	}
	text := callTool(t, cs, "get_inbox", map[string]any{"account_id": alice.acct.ID})
	if !strings.Contains(text, `"unread":1`) {
		t.Fatalf("get_inbox: %s", text)
	}
	threads, err := alice.st.ListThreadsByAccount(ctx, alice.acct.ID)
	if err != nil || len(threads) != 1 {
		t.Fatalf("threads: %v %d", err, len(threads))
	}
	text = callTool(t, cs, "read_thread", map[string]any{"account_id": alice.acct.ID, "thread_id": threads[0].ID})
	if !strings.Contains(text, "dinner friday") || !strings.Contains(text, `"trust"`) {
		t.Fatalf("read_thread: %s", text)
	}
	text = callTool(t, cs, "send_to_contact", map[string]any{
		"account_id": alice.acct.ID, "contact_fpr": bella.kp.Fingerprint,
		"thread_id": threads[0].ID, "msg_id": "a1", "text": "friday works — 7pm?",
	})
	var sent messaging.Result
	if err := json.Unmarshal([]byte(text), &sent); err != nil {
		t.Fatalf("send_to_contact result: %s", text)
	}
	msgs, err := alice.msg.Thread(ctx, alice.acct.ID, threads[0].ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("thread after answer: %v %d", err, len(msgs))
	}
	if msgs[1].Sender != "agent" || msgs[1].Direction != "out" || msgs[1].Body != "friday works — 7pm?" {
		t.Fatalf("agent answer: %+v", msgs[1])
	}

	// 8. The portal inbox shows the exchange (and opening marks it read).
	if code, body := get(t, clientA, srvA.URL+"/api/threads/"+threads[0].ID+"?account="+alice.acct.ID); code != 200 ||
		!strings.Contains(body, "dinner friday") || !strings.Contains(body, "friday works") {
		t.Fatalf("thread payload: %d\n%s", code, body)
	}
	if n, _ := alice.st.UnreadCount(ctx, alice.acct.ID, threads[0].ID); n != 0 {
		t.Fatalf("unread after portal open: %d", n)
	}
}

func callTool(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: empty result", tool)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: non-text content", tool)
	}
	if res.IsError {
		t.Fatalf("%s errored: %s", tool, tc.Text)
	}
	return tc.Text
}

func openSQLite(t *testing.T, name string) store.Store {
	t.Helper()
	s, err := store.OpenSQLite(t.TempDir() + "/" + name + ".db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var pgSeq int

func openPostgres(t *testing.T, dsn, name string) store.Store {
	t.Helper()
	pgSeq++
	dbName := fmt.Sprintf("pact_exit_%s_%d", name, pgSeq)
	admin, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	admin.Close(context.Background())
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + dbName
	s, err := store.OpenPostgres(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
