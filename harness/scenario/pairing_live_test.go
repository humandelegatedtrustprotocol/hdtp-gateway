package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/owner"
	"github.com/tech-sumit/pact-gateway/harness/peer"
	"github.com/tech-sumit/pact-gateway/harness/portal"
)

// PlaintextCanary is planted in message bodies so the relay invariant has an
// unmistakable string to look for (see harness/invariant).
const PlaintextCanary = "PACT-PLAINTEXT-CANARY"

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func dockerRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("PACT_HARNESS_LIVE") == "" {
		t.Skip("set PACT_HARNESS_LIVE=1 to run live scenarios")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := dockerRunner(ctx, "docker", "image", "inspect", nodeImage); err != nil {
		t.Skipf("%s not built — run `make harness-image`", nodeImage)
	}
}

// S2 — pairing, end to end, through every surface the product actually has:
// the setup wizard in a real browser, the owner MCP over a bearer token, and a
// contact's agent over real mTLS. Nothing is stubbed and nothing is in-process.
//
// This is the scenario P10-12i was written for. Until it ran, "two people can pair
// and exchange a message" was proven only by tests that drove outbound.Client
// directly inside one process.
func TestPairingAndMessagingEndToEnd(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	f := fabric.New("pactpair", dockerRunner)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		dir := os.Getenv("PACT_HARNESS_ARTIFACTS")
		if dir != "" {
			_ = f.Collect(c, dir)
		}
		_ = f.Teardown(c)
	})

	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	const ownerPort, publicPort = "18601", "18602"
	node, err := f.Container(ctx, fabric.Spec{
		Name: "alice", Image: nodeImage, Network: net,
		Ports: []string{ownerPort + ":8081", publicPort + ":8443"},
		Env: map[string]string{
			"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
			"PACT_PUBLIC_URL":    "https://127.0.0.1:" + publicPort,
			"PACT_INTERNAL_BIND": "127.0.0.1:8080",
			"PACT_CLIENT_CERT":   "preferred",
			// Guest onboarding requires direct mode with sealing OPTIONAL: a guest
			// has no way to seal to a node whose key it has not yet received, and
			// receiving it is what redemption is for (SPEC 9.2).
			"PACT_SEAL": "optional",
		},
		Cmd: []string{"serve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitHealthy(t, ctx, f, node)

	acct, err := f.Exec(ctx, node, "/pact-gateway", "account", "create", "--slug", "alice", "--name", "Alice")
	if err != nil {
		t.Fatalf("creating account: %v (%s)", err, acct)
	}
	nodeFpr := firstField(string(acct), "sha256:")
	if nodeFpr == "" {
		t.Fatalf("no fingerprint in %q", acct)
	}

	// The internal surface is loopback-bound (SPEC §8.3). A sidecar in the node's
	// own network namespace reaches it without the node binding non-loopback.
	if _, err := f.Container(ctx, fabric.Spec{
		Name: "ownerbridge", Image: "alpine/socat",
		NetworkMode: "container:" + node.Name,
		Cmd:         []string{"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"},
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	// --- the owner registers a passkey in a real browser -------------------
	setupTok := setupToken(t, ctx, f, node)
	br, err := portal.Open(ctx)
	if err != nil {
		t.Fatalf("launching Chrome: %v", err)
	}
	defer br.Close()
	// localhost, not 127.0.0.1: an IP is not a valid WebAuthn RP ID, and the node
	// correctly refuses to bind credentials to one (internal/internalui/origin.go).
	msg, err := br.RegisterFirstPasskey(ctx,
		fmt.Sprintf("http://localhost:%s/setup?token=%s", ownerPort, setupTok), "harness")
	if err != nil {
		t.Fatalf("wizard: %v (said %q)", err, msg)
	}

	// No restart: an account created on a running node is servable immediately
	// since P14-05a. If that regresses, this scenario fails — which is the point.

	// --- the owner's agent connects over the owner MCP ---------------------
	ownerID := firstField(execOut(t, ctx, f, node, "/pact-gateway", "passkey", "list"), "owner=")
	ownerID = strings.TrimPrefix(ownerID, "owner=")
	tokLine := execOut(t, ctx, f, node, "/pact-gateway", "token", "create", "-owner", ownerID, "-label", "harness")
	token := ""
	for _, l := range strings.Split(tokLine, "\n") {
		if strings.Contains(l, "shown once") {
			token = strings.TrimSpace(l[strings.LastIndex(l, ":")+1:])
		}
	}
	if token == "" {
		t.Fatalf("no owner token in %q", tokLine)
	}

	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+ownerPort+"/owner/mcp", token)
	if err != nil {
		t.Fatalf("owner MCP: %v", err)
	}
	defer oc.Close()

	accounts, err := oc.Accounts(ctx)
	if err != nil {
		t.Fatalf("list_accounts: %v", err)
	}
	// P14-05c: this returned null on every node until membership was granted.
	if len(accounts) != 1 {
		t.Fatalf("owner administers %d accounts, want 1 — membership is not being granted", len(accounts))
	}

	// --- the owner issues an invite ----------------------------------------
	inviteRaw, err := oc.Call(ctx, "create_invite", map[string]any{
		"account_id": accounts[0], "label": "harness contact", "max_uses": 1,
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var invite struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	_ = json.Unmarshal([]byte(inviteRaw), &invite)
	if invite.Token == "" {
		// Some builds return the token inside the URL only.
		if i := strings.LastIndex(invite.URL, "/i/"); i >= 0 {
			invite.Token = invite.URL[i+3:]
		}
	}
	if invite.Token == "" {
		t.Fatalf("create_invite returned no usable token: %s", inviteRaw)
	}

	// --- a contact's agent redeems it over real mTLS -----------------------
	bob, err := peer.NewAgent("bob")
	if err != nil {
		t.Fatal(err)
	}
	target := peer.Target{
		Endpoint: "https://127.0.0.1:" + publicPort + "/a/alice/mcp",
		Root:     nodeFpr,
	}
	names, err := bob.ListTools(ctx, target)
	if err != nil {
		t.Fatalf("bob could not reach alice's public surface: %v", err)
	}
	if !contains(names, "redeem_invite") {
		t.Fatalf("guest surface has no redeem_invite: %v", names)
	}
	// --- bob redeems the invite, exchanging cards ---------------------------
	redeemed, err := bob.Call(ctx, target, "redeem_invite", map[string]any{
		"token": invite.Token, "card": bob.Card("optional"),
	}, "redeem-1")
	if err != nil {
		t.Fatalf("redeem_invite: %v", err)
	}
	t.Logf("redeem_invite -> %s", shorten(redeemed, 160))

	// --- the owner sees the request and approves it -------------------------
	listRaw, err := oc.Call(ctx, "list_contacts", map[string]any{"account_id": accounts[0]})
	if err != nil {
		t.Fatalf("list_contacts: %v", err)
	}
	t.Logf("contacts after redemption -> %s", shorten(listRaw, 200))
	if !strings.Contains(listRaw, bob.Fingerprint()) {
		t.Fatalf("bob is not on alice's contact list after redeeming: %s", listRaw)
	}
	if _, aerr := oc.Call(ctx, "approve_contact", map[string]any{
		"account_id": accounts[0], "contact_fpr": bob.Fingerprint(), "preset": "friend",
	}); aerr != nil {
		t.Fatalf("approve_contact: %v", aerr)
	}

	after, _ := oc.Call(ctx, "list_contacts", map[string]any{"account_id": accounts[0]})
	t.Logf("contacts AFTER approval -> %s", shorten(after, 320))

	afterTools, terr := bob.ListTools(ctx, target)
	t.Logf("bob's surface AFTER approval -> %v (err=%v)", afterTools, terr)

	// DIAGNOSTIC: if a restart widens the surface, the store is right and the
	// per-caller server cache is stale — i.e. approve_contact never invalidated
	// it (P14-05e).
	if !contains(afterTools, "send_message") {
		if _, rerr := f.Raw(ctx, "docker", "restart", node.Name); rerr != nil {
			t.Fatal(rerr)
		}
		waitHealthy(t, ctx, f, node)
		time.Sleep(2 * time.Second)
		restarted, _ := bob.ListTools(ctx, target)
		t.Logf("bob's surface AFTER RESTART -> %v", restarted)
		if contains(restarted, "send_message") {
			t.Logf("CONFIRMED: the store was correct; the cached per-caller server was stale")
		}
	}

	// --- bob sends a message over real mTLS ---------------------------------
	body := "hello from the harness " + PlaintextCanary
	sent, serr := bob.Call(ctx, target, "send_message", map[string]any{
		"text": body, "sender": "agent", "msg_id": "harness-msg-1",
	}, "harness-msg-1")
	if serr != nil {
		t.Fatalf("send_message: %v", serr)
	}
	t.Logf("send_message -> %s", shorten(sent, 160))

	// --- and the owner's agent reads it back --------------------------------
	inbox, ierr := oc.Call(ctx, "get_inbox", map[string]any{"account_id": accounts[0]})
	if ierr != nil {
		t.Fatalf("get_inbox: %v", ierr)
	}
	// get_inbox returns thread SUMMARIES (thread_id, contact_fpr, unread, last_at),
	// not bodies — the body lives behind read_thread. An earlier version of this
	// test looked for the message text in the summary and "failed" on a message
	// that had in fact been delivered.
	var threads []struct {
		ThreadID string `json:"thread_id"`
		Unread   int    `json:"unread"`
	}
	if uerr := json.Unmarshal([]byte(inbox), &threads); uerr != nil {
		t.Fatalf("get_inbox returned unparseable JSON %q: %v", shorten(inbox, 200), uerr)
	}
	if len(threads) != 1 || threads[0].Unread != 1 {
		t.Fatalf("inbox should hold exactly one thread with one unread message, got %s", shorten(inbox, 300))
	}
	body2, rerr := oc.Call(ctx, "read_thread", map[string]any{
		"account_id": accounts[0], "thread_id": threads[0].ThreadID,
	})
	if rerr != nil {
		t.Fatalf("read_thread: %v", rerr)
	}
	if !strings.Contains(body2, PlaintextCanary) {
		t.Fatalf("the message bob sent over mTLS never reached alice's thread: %s", shorten(body2, 400))
	}
	t.Logf("read_thread -> %s", shorten(body2, 200))

	t.Logf("guest surface: %v", names)
	t.Logf("invite token: %s…", invite.Token[:min(8, len(invite.Token))])
	t.Logf("owner accounts: %v", accounts)
	t.Logf("wizard: %s", msg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func firstField(out, prefix string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, prefix) {
			return f
		}
	}
	return ""
}

func execOut(t *testing.T, ctx context.Context, f *fabric.Fabric, c *fabric.Container, args ...string) string {
	t.Helper()
	out, err := f.Exec(ctx, c, args...)
	if err != nil {
		t.Fatalf("exec %v: %v (%s)", args, err, out)
	}
	return string(out)
}

func setupToken(t *testing.T, ctx context.Context, f *fabric.Fabric, c *fabric.Container) string {
	t.Helper()
	out, err := f.Raw(ctx, "docker", "logs", c.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, fl := range strings.Fields(string(out)) {
		if i := strings.Index(fl, "token="); i >= 0 {
			return fl[i+6:]
		}
	}
	t.Fatalf("no setup token in logs:\n%s", out)
	return ""
}

func waitHealthy(t *testing.T, ctx context.Context, f *fabric.Fabric, c *fabric.Container) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := f.Exec(ctx, c, "/pact-gateway", "healthcheck"); err == nil {
			return
		}
		if time.Now().After(deadline) {
			out, _ := f.Raw(ctx, "docker", "logs", c.Name)
			t.Fatalf("%s never became healthy:\n%s", c.Name, out)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
