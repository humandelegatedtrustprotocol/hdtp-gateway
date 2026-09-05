package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/relay"
)

// runServeCfg starts serve against a caller-supplied config map.
func runServeCfg(t *testing.T, dir string, cfg map[string]any, seed func(*testing.T, string)) *running {
	t.Helper()
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
	return startServeAt(t, dir, cfgPath, cfg["internal_bind"].(string), cfg["public_bind"].(string))
}

// AC (P6-04): a node configured with a gateway publishes X-PACT-GATEWAY on its
// card, and a node configured to relay accepts relay_call from an allow-listed
// sender over its real public listener.
func TestRelayRoleAndGatewayOnTheCard(t *testing.T) {
	ctx := context.Background()

	// ---- the RELAY node: serves /relay/mcp for other people ----
	relayDir := t.TempDir()
	relayInternal, relayPublic := freePort(t), freePort(t)
	runServeCfg(t, relayDir, map[string]any{
		"data_dir": relayDir, "internal_bind": relayInternal, "public_bind": relayPublic,
		"public_url": "https://" + relayPublic, "relay": true,
		"seal": "optional", "client_cert": "preferred",
	}, func(t *testing.T, dir string) {
		st := migrated(t, dir)
		defer st.Close()
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		if _, err := idm.CreateAccount(ctx, "hub", "Hub", identity.AlgoP256); err != nil {
			t.Fatal(err)
		}
	})

	// the relay's own identity, which the recipient must pin: a self-signed
	// relay is not WebPKI-valid, and trusting it unpinned would trust anyone
	// who can answer on that address.
	relayFpr := accountFingerprint(t, relayDir, "hub")

	// ---- the recipient: publishes that relay as its gateway ----
	nodeDir := t.TempDir()
	nodeInternal, nodePublic := freePort(t), freePort(t)
	gateway := "https://" + relayPublic
	var acct store.Account
	senderKP, senderCert := peerIdentity(t, "alice")
	runServeCfg(t, nodeDir, map[string]any{
		"data_dir": nodeDir, "internal_bind": nodeInternal, "public_bind": nodePublic,
		"public_url": "https://" + nodePublic, "gateway_url": gateway,
		"gateway_fingerprint": relayFpr,
		"seal":                "optional", "client_cert": "preferred",
	}, func(t *testing.T, dir string) {
		st := migrated(t, dir)
		defer st.Close()
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		a, err := idm.CreateAccount(ctx, "bob", "Bob", identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		acct = a
		if _, err := st.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: senderKP.Fingerprint,
			SPKI: mustSPKI(t, senderKP), Status: "active", Permissions: []string{"message.text"},
		}); err != nil {
			t.Fatal(err)
		}
	})

	// the card advertises the gateway — without it no peer could fall back
	nst := openStoreAt(t, nodeDir)
	kp := loadAccountKey(t, nodeDir, nst, acct.ID)
	client := &outbound.Client{Keypair: senderKP, Cert: senderCert, Roots: x509.NewCertPool()}
	peer := outbound.Peer{Endpoint: "https://" + nodePublic + "/a/bob/mcp", Fingerprint: acct.Fingerprint}
	res, err := client.CallTool(ctx, peer, "get_card", map[string]any{}, outbound.CallOptions{Plaintext: true})
	if err != nil || res.IsError {
		t.Fatalf("get_card: %v %+v", err, res)
	}
	var card struct {
		Card string `json:"card"`
	}
	if err := json.Unmarshal([]byte(textOf(res)), &card); err != nil {
		t.Fatalf("card body: %s", textOf(res))
	}
	if !strings.Contains(card.Card, "X-PACT-GATEWAY:"+gateway) {
		t.Fatalf("card carries no gateway:\n%s", card.Card)
	}

	// ---- the sender queues at that relay after a failed direct delivery ----
	// Bob's node syncs its allow-list on startup, so Alice is already allowed.
	waitForAllowlist(t, relayDir, kp.Fingerprint, senderKP.Fingerprint)

	inner, _ := json.Marshal(map[string]any{
		"method": "tools/call",
		"params": map[string]any{"name": "send_message",
			"arguments": map[string]any{"msg_id": "relayed-1", "text": "queued while you were away"}},
	})
	pub, err := x509.ParsePKIXPublicKey(mustSPKI(t, kp))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	env, err := envelope.Seal(envelope.SealParams{
		Sender: senderKP, RecipientPub: pub, To: kp.Fingerprint, MsgID: "relayed-1",
		TS: now.Unix(), Exp: now.Add(24 * time.Hour).Unix(), CTY: "application/pact-call+json",
	}, inner)
	if err != nil {
		t.Fatal(err)
	}
	fb := relay.Fallback{
		Direct: func(context.Context) error { return errDirectDown },
		RelayTransport: gatewayTransport{client: client,
			peer: outbound.Peer{Endpoint: gateway + "/relay/mcp", Fingerprint: relayFpr}},
	}
	path, err := fb.Deliver(ctx, kp.Fingerprint, env)
	if err != nil || path != "relay" {
		t.Fatalf("fallback to the running relay: path=%s err=%v", path, err)
	}
	// the relay stored it, and stored ciphertext only
	rst := openStoreAt(t, relayDir)
	if n, _ := rst.CountRelayQueue(ctx, kp.Fingerprint, time.Now().Unix()); n != 1 {
		t.Fatalf("queued %d items at the relay", n)
	}
	items, err := rst.FetchRelayQueue(ctx, kp.Fingerprint, time.Now().Unix(), 8)
	if err != nil || len(items) != 1 {
		t.Fatalf("fetch: %d %v", len(items), err)
	}
	if strings.Contains(items[0].Envelope, "queued while you were away") {
		t.Fatal("the relay stored plaintext")
	}

	// ---- and Bob's own fetch loop drains it into his store ----
	deadline := time.Now().Add(60 * time.Second)
	arrived := false
	for time.Now().Before(deadline) {
		if countMessages(t, nst, acct.ID) == 1 {
			arrived = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !arrived {
		t.Fatalf("the relayed message never arrived (relay queue still holds %d)",
			mustCount(t, rst, kp.Fingerprint))
	}

	// ---- a replayed envelope is handled, never re-executed (PACT §13.3) ----
	// A malicious or faulty relay can re-serve a fetched item any time until
	// its exp; the recipient's envelope idempotency is the only defence, and
	// this path used to skip it entirely. Queue the SAME envelope again and
	// let the real fetch loop drain it: the queue must empty (the replay was
	// acked, or it would wedge and refetch forever) and the message count must
	// stay at one.
	if _, err := fb.Deliver(ctx, kp.Fingerprint, env); err != nil {
		t.Fatalf("re-queueing the same envelope: %v", err)
	}
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if mustCount(t, rst, kp.Fingerprint) == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if n := mustCount(t, rst, kp.Fingerprint); n != 0 {
		t.Fatalf("the replayed envelope wedged the queue (%d items)", n)
	}
	if n := countMessages(t, nst, acct.ID); n != 1 {
		t.Fatalf("the replayed envelope was re-executed: %d messages", n)
	}
	// The inner send_message carries its own msg_id, whose tool-level
	// idempotency would ALSO have kept the count at one — so pin the envelope
	// level specifically: the replay must be caught before dispatch, which is
	// the audited "replayed" outcome only that path writes.
	rows, err := nst.ListAuditEventsPage(ctx, store.AuditPage{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	replayedSeen := false
	for _, row := range rows {
		if row.Action == "sealed_call" && row.Outcome == "replayed" {
			replayedSeen = true
			break
		}
	}
	if !replayedSeen {
		t.Fatalf("no envelope-level replay was recorded — the duplicate reached dispatch")
	}
}

// AC (P6-04): a relay may not be mounted on an edge-mode listener.
func TestRelayRefusedInEdgeMode(t *testing.T) {
	cfg, err := core.Load("", func(k string) (string, bool) {
		switch k {
		case "PACT_RELAY":
			return "true", true
		case "PACT_MODE":
			return "edge", true
		case "PACT_SEAL":
			return "required", true
		case "PACT_CLIENT_CERT":
			return "off", true
		}
		return "", false
	})
	if err == nil {
		t.Fatalf("a relay was accepted in edge mode: %+v", cfg)
	}
	if !strings.Contains(err.Error(), core.RuleRelayEdge) {
		t.Fatalf("error should name the rule: %v", err)
	}
}

// AC (P6-04): the ingress role has a real entry point, in the shape
// docs/demos/own-domain.md documents, and validates its inputs.
func TestIngressCommandRequiresDomainAndToken(t *testing.T) {
	if code, _, errb := runQuiet("ingress"); code == 0 || !strings.Contains(errb, "serve|token") {
		t.Fatalf("bare ingress: code=%d err=%q", code, errb)
	}
	if code, _, errb := runQuiet("ingress", "serve"); code == 0 || !strings.Contains(errb, "-domain is required") {
		t.Fatalf("ingress serve with no domain: code=%d err=%q", code, errb)
	}
	if code, _, errb := runQuiet("ingress", "serve", "-domain", "example.test"); code == 0 ||
		!strings.Contains(errb, "data-plane token") {
		t.Fatalf("ingress serve with no token: code=%d err=%q", code, errb)
	}
	// `ingress token` needs a running ingress: without one it fails clearly
	// rather than minting something nothing will honor.
	if code, _, errb := runQuiet("ingress", "token", "-data-dir", t.TempDir()); code == 0 || errb == "" {
		t.Fatalf("ingress token with no running ingress: code=%d err=%q", code, errb)
	}
}

/* -------------------------------- helpers ------------------------------- */

var errDirectDown = &directDownError{}

type directDownError struct{}

func (*directDownError) Error() string { return "dial tcp: connection refused" }

// accountFingerprint reads an account's pinned fingerprint from a served store.
func accountFingerprint(t *testing.T, dir, slug string) string {
	t.Helper()
	st := openStoreAt(t, dir)
	accts, err := st.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accts {
		if a.Slug == slug {
			return a.Fingerprint
		}
	}
	t.Fatalf("no account %s in %s", slug, dir)
	return ""
}

func migrated(t *testing.T, dir string) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func peerIdentity(t *testing.T, cn string) (*identity.Keypair, tls.Certificate) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, cn)
	if err != nil {
		t.Fatal(err)
	}
	return kp, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
}

func mustSPKI(t *testing.T, kp *identity.Keypair) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadAccountKey(t *testing.T, dir string, st store.Store, accountID string) *identity.Keypair {
	t.Helper()
	sealed, err := st.GetAccountSealedKey(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	kp, err := idm.LoadKeypair(sealed)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func waitForAllowlist(t *testing.T, relayDir, recipient, sender string) {
	t.Helper()
	rst := openStoreAt(t, relayDir)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := rst.RelayAllowed(context.Background(), recipient, sender); ok {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the recipient never synced its allow-list to the relay")
}

func countMessages(t *testing.T, st store.Store, accountID string) int {
	t.Helper()
	ctx := context.Background()
	threads, _ := st.ListThreadsByAccount(ctx, accountID)
	n := 0
	for _, th := range threads {
		msgs, _ := st.ListMessagesByThread(ctx, accountID, th.ID)
		n += len(msgs)
	}
	return n
}

func mustCount(t *testing.T, st store.Store, fpr string) int64 {
	t.Helper()
	n, _ := st.CountRelayQueue(context.Background(), fpr, time.Now().Unix())
	return n
}

func textOf(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}
