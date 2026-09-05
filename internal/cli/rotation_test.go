package cli

// P10-09a: `account rotate` proven against a live peer, through the shipped binary.
//
// Nothing tested this path before. `internal/contacts` proved the receiver's
// rules with the NEW key handed in directly, which is not what the wire carries:
// SPEC §3.9 step 4 says the rotating node calls with its OLD certificate, and
// cli.go builds exactly that client. The two halves therefore disagreed, and no
// test could see it because no test ran both halves.

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// AC (P10-09a): a rotation issued on one running node re-pins a real contact on
// another running node, and the peer ends up holding the NEW fingerprint.
func TestAccountRotateRepinsALivePeer(t *testing.T) {
	ctx := context.Background()

	aDir, bDir := t.TempDir(), t.TempDir()
	aInt, aPub := freePort(t), freePort(t)
	bInt, bPub := freePort(t), freePort(t)
	aEndpoint := "https://" + aPub + "/a/alice/mcp"
	bEndpoint := "https://" + bPub + "/a/bob/mcp"

	// Alice's identity has to exist before Bob can pin her, and Bob's before
	// Alice can call him — so both accounts are created first, then both nodes
	// start with each other already pinned.
	aFpr, aSPKI := seedIdentity(t, aDir, "alice", "Alice")
	bFpr, bSPKI := seedIdentity(t, bDir, "bob", "Bob")

	pin(t, bDir, "bob", store.Contact{
		Fingerprint: aFpr, SPKI: aSPKI, Status: "active",
		Card: cardFor(t, "Alice", aFpr, aEndpoint), Permissions: []string{"message.text"},
	})
	pin(t, aDir, "alice", store.Contact{
		Fingerprint: bFpr, SPKI: bSPKI, Status: "active",
		Card: cardFor(t, "Bob", bFpr, bEndpoint), Permissions: []string{"message.text"},
	})

	base := func(dir, internal, public, slug string) map[string]any {
		return map[string]any{
			"data_dir": dir, "internal_bind": internal, "public_bind": public,
			"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
		}
	}
	runServeCfg(t, bDir, base(bDir, bInt, bPub, "bob"), nil)
	runServeCfg(t, aDir, base(aDir, aInt, aPub, "alice"), nil)

	// Rotate Alice's key through the admin socket — the command an owner runs.
	var out map[string]any
	if err := core.AdminCall(core.AdminSocketPath(aDir), "account.rotate",
		map[string]string{"slug": "alice", "grace": "24h"}, &out); err != nil {
		t.Fatalf("account.rotate: %v", err)
	}
	// The admin reply capitalises these; reading the lower-case names made the
	// assertion vacuous, which is how a broken fan-out passed for a while.
	if f, _ := out["Failed"].(float64); f != 0 {
		t.Fatalf("the fan-out could not re-pin a live peer: %+v", out)
	}
	if d, _ := out["Done"].(float64); d != 1 {
		t.Fatalf("the fan-out reported %v completions, want 1: %+v", out["Done"], out)
	}

	newFpr := accountFingerprint(t, aDir, "alice")
	if newFpr == aFpr {
		t.Fatal("rotation did not change Alice's fingerprint")
	}

	// Bob must now hold the NEW fingerprint. Before P10-09a he held the old one
	// and every rotation was refused `identity_required`.
	bst := openStoreAt(t, bDir)
	deadline := time.Now().Add(10 * time.Second)
	for {
		list, _ := bst.ListContacts(ctx, accountIDOf(t, bst, "bob"))
		for _, c := range list {
			if c.Fingerprint == newFpr && c.Status == "active" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Bob never re-pinned Alice to %s; he still holds %+v", newFpr, list)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func seedIdentity(t *testing.T, dir, slug, name string) (fpr string, spki []byte) {
	t.Helper()
	st := migrated(t, dir)
	defer st.Close()
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	a, err := idm.CreateAccount(context.Background(), slug, name, identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := st.GetAccountSealedKey(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := idm.LoadKeypair(sealed)
	if err != nil {
		t.Fatal(err)
	}
	return a.Fingerprint, mustSPKI(t, kp)
}

func pin(t *testing.T, dir, slug string, c store.Contact) {
	t.Helper()
	st := migrated(t, dir)
	defer st.Close()
	c.AccountID = accountIDOf(t, st, slug)
	if _, err := st.InsertContact(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func accountIDOf(t *testing.T, st store.Store, slug string) string {
	t.Helper()
	accts, err := st.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accts {
		if a.Slug == slug {
			return a.ID
		}
	}
	t.Fatalf("no account %q", slug)
	return ""
}

// cardFor builds a peer's card the way that peer's node would: a real card
// always states its seal policy, and the sender obeys what the card says.
func cardFor(t *testing.T, name, fpr, endpoint string) string {
	t.Helper()
	return cardWithGateway(t, name, fpr, endpoint, "")
}

// cardWithGateway is cardFor plus an X-PACT-GATEWAY, which is what makes a
// contact reachable through a relay when direct delivery fails (§7.1).
func cardWithGateway(t *testing.T, name, fpr, endpoint, gateway string) string {
	t.Helper()
	card, err := contacts.BuildCard(contacts.Card{
		FN: name, Key: fpr, Endpoint: endpoint, Seal: "required", Gateway: gateway,
	})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// AC (P10-07a): a message composed on one node reaches the OTHER node's store.
//
// This is the thing pact-gateway could not do. Both outbound origins called
// messaging.Service.Record, which writes a local row and returns; the package
// imports only the store and has no path to the wire. So the portal reported
// "delivered", the row said "delivered", and nothing left the machine. Every
// two-node test passed because the tests drove outbound.Client themselves.
func TestOwnerComposedMessageReachesThePeersStore(t *testing.T) {
	ctx := context.Background()

	aDir, bDir := t.TempDir(), t.TempDir()
	aInt, aPub := freePort(t), freePort(t)
	bInt, bPub := freePort(t), freePort(t)
	aEndpoint := "https://" + aPub + "/a/alice/mcp"
	bEndpoint := "https://" + bPub + "/a/bob/mcp"

	aFpr, aSPKI := seedIdentity(t, aDir, "alice", "Alice")
	bFpr, bSPKI := seedIdentity(t, bDir, "bob", "Bob")

	// Each pins the other, and Bob grants Alice message.text.
	pin(t, bDir, "bob", store.Contact{
		Fingerprint: aFpr, SPKI: aSPKI, Status: "active",
		Card: cardFor(t, "Alice", aFpr, aEndpoint), Permissions: []string{"message.text"},
	})
	pin(t, aDir, "alice", store.Contact{
		Fingerprint: bFpr, SPKI: bSPKI, Status: "active",
		Card: cardFor(t, "Bob", bFpr, bEndpoint), Permissions: []string{"message.text"},
	})

	cfg := func(dir, internal, public string) map[string]any {
		return map[string]any{
			"data_dir": dir, "internal_bind": internal, "public_bind": public,
			"public_url": "https://" + public, "client_cert": "preferred",
		}
	}
	runServeCfg(t, bDir, cfg(bDir, bInt, bPub), nil)
	ra := runServeCfg(t, aDir, cfg(aDir, aInt, aPub), nil)

	// Alice sends from her portal, exactly as an owner would.
	ast := openStoreAt(t, aDir)
	aAcct := accountIDOf(t, ast, "alice")
	p := newPortal(t, "http://"+ra.internal)
	body := p.post("/threads/t-p10-07a/send?account="+aAcct+"&contact="+bFpr, url.Values{
		"msg_id": {"m-p10-07a"}, "text": {"this must actually arrive"},
	})
	if strings.Contains(body, "delivery failed") {
		t.Fatalf("the portal could not deliver: %s", firstLine(body))
	}

	// It must exist on BOB's node, not merely in Alice's own table.
	bst := openStoreAt(t, bDir)
	bAcct := accountIDOf(t, bst, "bob")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if m, err := bst.GetMessageByMsgID(ctx, bAcct, aFpr, "in", "m-p10-07a"); err == nil {
			if m.Body != "this must actually arrive" {
				t.Fatalf("arrived corrupted: %q", m.Body)
			}
			if m.Direction != "in" {
				t.Fatalf("recorded on the peer as %q", m.Direction)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the message never reached the peer's store — nothing left the machine")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// And Alice's own row must say delivered, having actually been delivered.
	own, err := ast.GetMessageByMsgID(ctx, aAcct, bFpr, "out", "m-p10-07a")
	if err != nil {
		t.Fatalf("the sender kept no record: %v", err)
	}
	if own.Status != "delivered" {
		t.Fatalf("sender row status = %q, want delivered", own.Status)
	}
}

// AC (P10-07b): a send that fails is retried until its deadline, and then said
// to have failed. SPEC §7.1 requires retry-with-backoff until the sender-chosen
// `expires` (default 24 h) reusing the SAME msg_id, so the recipient's
// idempotency handling makes the retry path safe.
func TestUndeliveredMessageIsRetriedThenExpires(t *testing.T) {
	ctx := context.Background()

	aDir, bDir := t.TempDir(), t.TempDir()
	aInt, aPub := freePort(t), freePort(t)
	bInt, bPub := freePort(t), freePort(t)
	aEndpoint := "https://" + aPub + "/a/alice/mcp"
	bEndpoint := "https://" + bPub + "/a/bob/mcp"

	aFpr, aSPKI := seedIdentity(t, aDir, "alice", "Alice")
	bFpr, bSPKI := seedIdentity(t, bDir, "bob", "Bob")
	pin(t, bDir, "bob", store.Contact{
		Fingerprint: aFpr, SPKI: aSPKI, Status: "active",
		Card: cardFor(t, "Alice", aFpr, aEndpoint), Permissions: []string{"message.text"},
	})
	pin(t, aDir, "alice", store.Contact{
		Fingerprint: bFpr, SPKI: bSPKI, Status: "active",
		Card: cardFor(t, "Bob", bFpr, bEndpoint), Permissions: []string{"message.text"},
	})
	cfg := func(dir, internal, public string) map[string]any {
		return map[string]any{
			"data_dir": dir, "internal_bind": internal, "public_bind": public,
			"public_url": "https://" + public, "client_cert": "preferred",
		}
	}
	// Bob is NOT started: Alice's send must fail and stay recoverable.
	ra := runServeCfg(t, aDir, cfg(aDir, aInt, aPub), nil)

	ast := openStoreAt(t, aDir)
	aAcct := accountIDOf(t, ast, "alice")
	p := newPortal(t, "http://"+ra.internal)
	code, body := p.postExpectingStatus("/threads/t-retry/send?account="+aAcct+"&contact="+bFpr, url.Values{
		"msg_id": {"m-retry"}, "text": {"queued while you were away"},
	})
	if code == 200 {
		t.Fatalf("a send to an unreachable peer reported success: %s", firstLine(body))
	}
	if !strings.Contains(body, "recorded") {
		t.Fatalf("the failure did not say the message was kept: %s", firstLine(body))
	}

	// The message must still exist locally, marked pending — not lost, not lying.
	m, err := ast.GetMessageByMsgID(ctx, aAcct, bFpr, "out", "m-retry")
	if err != nil {
		t.Fatalf("a failed send lost the owner's message: %v", err)
	}
	if m.Status != "pending" {
		t.Fatalf("status after a failed send = %q, want pending", m.Status)
	}

	// Bob comes up. The sweeper must deliver it without the owner retyping it.
	runServeCfg(t, bDir, cfg(bDir, bInt, bPub), nil)
	bst := openStoreAt(t, bDir)
	bAcct := accountIDOf(t, bst, "bob")

	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := bst.GetMessageByMsgID(ctx, bAcct, aFpr, "in", "m-retry"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the retry sweep never delivered the pending message")
		}
		time.Sleep(500 * time.Millisecond)
	}
	own, _ := ast.GetMessageByMsgID(ctx, aAcct, bFpr, "out", "m-retry")
	if own.Status != "delivered" {
		t.Fatalf("sender row after a successful retry = %q, want delivered", own.Status)
	}
}

// AC (P10-07c): when direct delivery fails, the message is queued at the
// contact's published relay and arrives when they come back.
//
// relay.Fallback existed with zero production callers: the sender half of
// PACT §7 was written, tested and never wired, so X-PACT-GATEWAY on a contact's
// card meant nothing to this node.
//
// P13-04 corrected WHEN it is reached for. SPEC §7.1 orders it exactly: the node
// "retries with backoff until the sender-chosen `expires` … THEN falls back to
// the contact's X-PACT-GATEWAY relay". This test used to assert the opposite —
// that one refused connection was enough — which handed a third party the
// sender, recipient, size and timing of a message that direct delivery carried
// successfully moments later.
func TestDirectFailureDefersTheRelayUntilTheDeadline(t *testing.T) {
	ctx := context.Background()

	// A relay node Bob publishes as his gateway.
	rDir := t.TempDir()
	rInt, rPub := freePort(t), freePort(t)
	seedIdentity(t, rDir, "hub", "Hub")
	runServeCfg(t, rDir, map[string]any{
		"data_dir": rDir, "internal_bind": rInt, "public_bind": rPub,
		"public_url": "https://" + rPub, "relay": true,
		"seal": "optional", "client_cert": "preferred",
	}, nil)
	gateway := "https://" + rPub

	aDir, bDir := t.TempDir(), t.TempDir()
	aInt, aPub := freePort(t), freePort(t)
	bInt, bPub := freePort(t), freePort(t)
	aEndpoint := "https://" + aPub + "/a/alice/mcp"
	bEndpoint := "https://" + bPub + "/a/bob/mcp"

	aFpr, aSPKI := seedIdentity(t, aDir, "alice", "Alice")
	bFpr, bSPKI := seedIdentity(t, bDir, "bob", "Bob")
	pin(t, bDir, "bob", store.Contact{
		Fingerprint: aFpr, SPKI: aSPKI, Status: "active",
		Card: cardFor(t, "Alice", aFpr, aEndpoint), Permissions: []string{"message.text"},
	})
	// Alice holds Bob's card WITH his gateway. His endpoint is dead.
	pin(t, aDir, "alice", store.Contact{
		Fingerprint: bFpr, SPKI: bSPKI, Status: "active",
		Card:        cardWithGateway(t, "Bob", bFpr, bEndpoint, gateway),
		Permissions: []string{"message.text"},
	})

	cfg := func(dir, internal, public string) map[string]any {
		return map[string]any{
			"data_dir": dir, "internal_bind": internal, "public_bind": public,
			"public_url": "https://" + public, "client_cert": "preferred",
		}
	}
	// Bob comes up FIRST, pointed at the relay, so he syncs his allow-list —
	// a relay queues only for senders the recipient allowed (§10.5). Then he
	// goes dark, which is the situation the fallback exists for.
	bcfg := cfg(bDir, bInt, bPub)
	bcfg["gateway_url"] = gateway
	bcfg["gateway_fingerprint"] = accountFingerprint(t, rDir, "hub")
	rb := runServeCfg(t, bDir, bcfg, nil)
	rst0 := openStoreAt(t, rDir)
	waitFor(t, 20*time.Second, "Bob never synced his allow-list", func() bool {
		ok, _ := rst0.RelayAllowed(ctx, bFpr, aFpr)
		return ok
	})
	rb.stop()

	// Alice uses the same relay Bob publishes, so she holds its fingerprint and
	// pins it — the case a shared relay makes ordinary.
	acfg := cfg(aDir, aInt, aPub)
	acfg["gateway_url"] = gateway
	acfg["gateway_fingerprint"] = accountFingerprint(t, rDir, "hub")
	ra := runServeCfg(t, aDir, acfg, nil)

	// Bob is DOWN. Alice sends: direct fails, the relay takes it.
	ast := openStoreAt(t, aDir)
	aAcct := accountIDOf(t, ast, "alice")
	p := newPortal(t, "http://"+ra.internal)
	code, body := p.postExpectingStatus("/threads/t-relay/send?account="+aAcct+"&contact="+bFpr, url.Values{
		"msg_id": {"m-relay"}, "text": {"sent while you slept"},
	})
	if code == 200 {
		t.Fatalf("a send to an unreachable peer reported success: %s", firstLine(body))
	}

	// The relay must NOT have been told. Bob publishes an endpoint, so direct
	// delivery is still the plan and the relay has no business knowing this
	// message exists yet.
	rst := openStoreAt(t, rDir)
	items, err := rst.FetchRelayQueue(ctx, bFpr, time.Now().Unix(), 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("%d envelope(s) handed to a third-party relay on the first refused "+
			"connection — SPEC §7.1 defers that until the message's deadline", len(items))
	}

	// It is kept, pending, for the retry sweeper.
	m, err := ast.GetMessageByMsgID(ctx, aAcct, bFpr, "out", "m-relay")
	if err != nil {
		t.Fatalf("a deferred message was lost: %v", err)
	}
	if m.Status != "pending" {
		t.Fatalf("status after a deferred relay = %q, want pending", m.Status)
	}

	// Bob comes up. Direct delivery carries it, and the relay is never involved.
	runServeCfg(t, bDir, bcfg, nil)
	bst := openStoreAt(t, bDir)
	bAcct := accountIDOf(t, bst, "bob")
	waitFor(t, 90*time.Second, "the retry sweep never delivered the deferred message", func() bool {
		_, err := bst.GetMessageByMsgID(ctx, bAcct, aFpr, "in", "m-relay")
		return err == nil
	})
	// The sender's row is flipped to delivered only AFTER deliverWithExpiry
	// returns, which is strictly after the recipient has written and answered.
	// Reading it the instant the recipient's row appears races a window that is
	// guaranteed non-zero, and on a loaded runner under -race the window wins:
	// this assertion failed four CI runs across one afternoon while the product
	// behaved correctly every time.
	var own store.Message
	waitFor(t, 30*time.Second, "the sender's row never reached delivered", func() bool {
		own, _ = ast.GetMessageByMsgID(ctx, aAcct, bFpr, "out", "m-relay")
		return own.Status == "delivered"
	})
	if items, _ := rst.FetchRelayQueue(ctx, bFpr, time.Now().Unix(), 8); len(items) != 0 {
		t.Fatalf("the relay was handed %d envelope(s) for a message direct delivery carried", len(items))
	}
}

// waitFor polls until cond holds or the budget runs out.
func waitFor(t *testing.T, budget time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// AC (P10-07d): a relay-assisted contact — one whose card carries only
// X-PACT-GATEWAY and no endpoint (§9.3, §10.1) — is reachable. Delivery used to
// refuse outright for want of an endpoint, so the deployment mode the spec
// describes could never receive anything.
func TestGatewayOnlyContactIsReachable(t *testing.T) {
	ctx := context.Background()

	rDir := t.TempDir()
	rInt, rPub := freePort(t), freePort(t)
	seedIdentity(t, rDir, "hub", "Hub")
	runServeCfg(t, rDir, map[string]any{
		"data_dir": rDir, "internal_bind": rInt, "public_bind": rPub,
		"public_url": "https://" + rPub, "relay": true,
		"seal": "optional", "client_cert": "preferred",
	}, nil)
	gateway := "https://" + rPub
	hubFpr := accountFingerprint(t, rDir, "hub")

	aDir, bDir := t.TempDir(), t.TempDir()
	aInt, aPub := freePort(t), freePort(t)
	bInt, bPub := freePort(t), freePort(t)
	aFpr, aSPKI := seedIdentity(t, aDir, "alice", "Alice")
	bFpr, bSPKI := seedIdentity(t, bDir, "bob", "Bob")

	pin(t, bDir, "bob", store.Contact{
		Fingerprint: aFpr, SPKI: aSPKI, Status: "active",
		Card:        cardFor(t, "Alice", aFpr, "https://"+aPub+"/a/alice/mcp"),
		Permissions: []string{"message.text"},
	})
	// Bob's card has NO endpoint — only a gateway. This is relay-assisted mode.
	pin(t, aDir, "alice", store.Contact{
		Fingerprint: bFpr, SPKI: bSPKI, Status: "active",
		Card:        cardWithGateway(t, "Bob", bFpr, "", gateway),
		Permissions: []string{"message.text"},
	})

	cfg := func(dir, internal, public string) map[string]any {
		return map[string]any{
			"data_dir": dir, "internal_bind": internal, "public_bind": public,
			"public_url": "https://" + public, "client_cert": "preferred",
			"gateway_url": gateway, "gateway_fingerprint": hubFpr,
		}
	}
	rb := runServeCfg(t, bDir, cfg(bDir, bInt, bPub), nil)
	rst := openStoreAt(t, rDir)
	waitFor(t, 20*time.Second, "Bob never synced his allow-list", func() bool {
		ok, _ := rst.RelayAllowed(ctx, bFpr, aFpr)
		return ok
	})
	rb.stop()

	ra := runServeCfg(t, aDir, cfg(aDir, aInt, aPub), nil)
	ast := openStoreAt(t, aDir)
	aAcct := accountIDOf(t, ast, "alice")
	p := newPortal(t, "http://"+ra.internal)
	code, body := p.postExpectingStatus("/threads/t-gwonly/send?account="+aAcct+"&contact="+bFpr, url.Values{
		"msg_id": {"m-gwonly"}, "text": {"no endpoint, still reachable"},
	})
	if code != 200 {
		t.Fatalf("a gateway-only contact was unreachable: %d %s", code, firstLine(body))
	}

	runServeCfg(t, bDir, cfg(bDir, bInt, bPub), nil)
	bst := openStoreAt(t, bDir)
	bAcct := accountIDOf(t, bst, "bob")
	waitFor(t, 60*time.Second, "the message never reached the gateway-only contact", func() bool {
		_, err := bst.GetMessageByMsgID(ctx, bAcct, aFpr, "in", "m-gwonly")
		return err == nil
	})
}
