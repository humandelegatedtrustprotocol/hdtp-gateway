package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
)

// T3 — neither side is reachable, so the relay is the only path (SPEC §10.1).
//
// This was the last networking pattern asserted only at the recorder level: the
// topology test checked the argv Docker was ASKED for and never that a message
// crossed. It could not be built live until E16, because relay-assisted delivery
// needs both nodes to hold each other as contacts and nothing could make a node
// reach OUT to a peer — `pending_out` was specified and unreachable.
//
// The shape is the real one, not a convenience: contacts are exchanged while a
// path exists, and then both sides go dark. A phone that met someone on the same
// network and later sat behind CGNAT is the ordinary case, and it is the only
// case the protocol supports — a relay will not carry a FIRST contact, because
// its allow-list is exactly the recipient's active contacts (§10.5).
//
// What it proves, in order: the owner-initiated contact of E16 works against a
// real peer; a node with no inbound path at all still receives; and the relay
// carries ciphertext only.
func TestRelayCarriesAMessageWhenNeitherSideIsReachable(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	f := fabric.New("pactrelay", dockerRun)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if dir := os.Getenv("PACT_HARNESS_ARTIFACTS"); dir != "" {
			_ = f.Collect(c, dir)
		}
		_ = f.Teardown(c)
	})

	// --- three segments ---
	//
	// `meet` is where the two owners can still see each other, which is the only
	// window in which a first contact can be established at all: a relay will not
	// carry one, because its allow-list is exactly the recipient's existing
	// contacts (§10.5). `seg-alice` and `seg-bob` are separate bridge networks,
	// and Docker keeps separate networks isolated — so once both leave `meet`,
	// neither can reach the other by any route, which is the T3 premise.
	//
	// The relay sits on BOTH segments. That models the thing a relay actually is:
	// the one host both parties can still reach.
	meet, err := f.Network(ctx, "meet", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	segA, err := f.Network(ctx, "seg-alice", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	segB, err := f.Network(ctx, "seg-bob", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := f.Container(ctx, fabric.Spec{
		Name: "relay", Image: nodeImage, Network: segA,
		Env: map[string]string{
			"PACT_PUBLIC_BIND": "0.0.0.0:8443",
			"PACT_PUBLIC_URL":  "https://pactrelay-relay:8443",
			"PACT_RELAY":       "true",
			// A relay verifies senders by their client certificate, so it must
			// run on a listener that asks for one (SPEC §10.5).
			"PACT_CLIENT_CERT":   "preferred",
			"PACT_SEAL":          "optional",
			"PACT_INTERNAL_BIND": "127.0.0.1:8080",
		},
		Cmd: []string{"serve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.Raw(ctx, "docker", "network", "connect", segB.Name, relay.Name); err != nil {
		t.Fatalf("attaching the relay to bob's segment: %v (%s)", err, out)
	}
	if err := waitHealthyC(ctx, f, relay); err != nil {
		t.Fatal(err)
	}
	relayFpr := field(execS(ctx, f, relay, "/pact-gateway", "account", "create",
		"--slug", "relay", "--name", "Relay"), "sha256:")
	if relayFpr == "" {
		t.Fatal("the relay has no identity")
	}
	// Both sides address the relay by the SAME name. That is not cosmetic: a
	// contact's card advertises its gateway (`X-PACT-GATEWAY`), and the sender
	// only follows one it recognises as its own — so two different addresses for
	// one relay, which is what per-segment IPs would give, makes each side refuse
	// the other's gateway as unpinned. A real relay has one public address for
	// exactly this reason; Docker resolves the name per network, so each side
	// still reaches it on its own segment.
	relayURL := "https://" + relay.Name + ":8443"

	// --- two nodes, relay-assisted from the start ---
	//
	// PACT_MODE is env-only, not a settable knob, so it cannot be flipped later:
	// they are relay-assisted for their whole life, which also forces
	// seal=required. Guest redemption still works against that, because the
	// invite landing hands the redeemer the issuer's SPKI (§9.2) — which is
	// exactly what makes a sealed first contact possible.
	relayEnv := map[string]string{
		"PACT_MODE":                "relay-assisted",
		"PACT_SEAL":                "required",
		"PACT_GATEWAY_URL":         relayURL,
		"PACT_GATEWAY_FINGERPRINT": relayFpr,
	}
	alice, err := StartOwnedNode(ctx, f, nodeImage, segA, "alice", "18110",
		"https://pactrelay-alice:8443", relayEnv)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	// Bob publishes NO endpoint. That is what a relay-assisted node is: its card
	// carries only X-PACT-GATEWAY and the relay IS its inbound path (§9.3,
	// §10.1). It is also what makes the relay the FIRST choice rather than a
	// deadline fallback — §7.1 earns the relay only when the contact has no
	// endpoint, or when the message has run out of time, and a test cannot wait
	// out a 24-hour expiry.
	bob, err := StartOwnedNode(ctx, f, nodeImage, segB, "bob", "18111", "", relayEnv)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	// Both join `meet` for the introduction, and leave it afterwards.
	for _, n := range []*Owned{alice, bob} {
		if out, err := f.Raw(ctx, "docker", "network", "connect", meet.Name, n.Node.Name); err != nil {
			t.Fatalf("putting %s on the meeting segment: %v (%s)", n.Node.Name, err, out)
		}
	}

	// --- E16: BOB reaches out, because he is the one who cannot be reached ---
	//
	// This is the direction that had no implementation at all. Bob publishes no
	// endpoint, so nobody can ever call HIM to become a contact; the only way he
	// can have one is by reaching out himself, which is exactly the
	// `none --> pending_out` transition SPEC §9 specifies and nothing could take.
	// Alice is reachable on the meeting segment, so her invite is redeemable.
	//
	// auto_accept makes one call establish both directions: alice pins bob when
	// he redeems, and his own row goes active because her answer says accepted.
	inviteRaw, err := alice.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": alice.AccountID, "label": "for bob", "max_uses": 1, "auto_accept": true,
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var inv struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.URL == "" && inv.Token != "" {
		inv.URL = "https://" + alice.Node.Name + ":8443/i/" + inv.Token
	}
	if inv.URL == "" {
		t.Fatalf("no invite token in %s", shorten(inviteRaw, 200))
	}
	addRaw, err := bob.Owner.Call(ctx, "add_contact", map[string]any{
		"account_id": bob.AccountID, "invite_url": inv.URL,
	})
	if err != nil {
		t.Fatalf("add_contact: %v", err)
	}
	var added struct {
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
	}
	_ = json.Unmarshal([]byte(addRaw), &added)
	if added.Code != "" {
		t.Fatalf("add_contact refused: %s — %s", added.Code, added.Detail)
	}
	if added.Fingerprint != alice.Fpr {
		t.Fatalf("bob pinned %q, want alice's %q", added.Fingerprint, alice.Fpr)
	}
	if added.Status != "active" {
		t.Fatalf("an auto-accepting invite left the contact %q", added.Status)
	}
	// Bob decides what alice may do on HIS node. Redeeming her invite told him
	// what SHE grants HIM; it granted her nothing here, deliberately — an invite
	// must not be able to choose its own privileges on the machine that redeemed
	// it.
	if _, err := bob.Owner.Call(ctx, "set_permissions", map[string]any{
		"account_id": bob.AccountID, "contact_fpr": alice.Fpr,
		"permissions": []string{"message.text"},
	}); err != nil {
		t.Fatalf("granting alice permission to message bob: %v", err)
	}

	// Alice must now hold bob — with a card that carries a gateway and no
	// endpoint, which is what makes her send reach for the relay.
	aliceContacts := execOwner(ctx, t, alice, "list_contacts", map[string]any{
		"account_id": alice.AccountID})
	if !strings.Contains(aliceContacts, bob.Fpr) {
		t.Fatalf("alice does not hold bob as a contact: %s", shorten(aliceContacts, 400))
	}
	if !strings.Contains(aliceContacts, "X-PACT-GATEWAY") {
		t.Errorf("bob's stored card carries no gateway, so alice has nowhere to queue: %s",
			shorten(aliceContacts, 400))
	}

	// --- both go dark ---
	//
	// Leaving the meeting segment is the whole severance: separate Docker bridge
	// networks are isolated from each other, so alice's only remaining neighbour
	// is the relay, and bob's is the relay.
	for _, n := range []*Owned{alice, bob} {
		if out, err := f.Raw(ctx, "docker", "network", "disconnect", meet.Name, n.Node.Name); err != nil {
			t.Fatalf("cutting %s off the meeting segment: %v (%s)", n.Node.Name, err, out)
		}
	}
	bobIP, err := f.IPOn(ctx, bob.Node, segB)
	if err != nil {
		t.Fatal(err)
	}
	// The severance must be REAL, or everything after this proves nothing.
	probe, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", segA.Name,
		alpineImage, "sh", "-c",
		"nc -z -w3 "+bobIP+" 8443 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
	if !strings.Contains(string(probe), "BLOCKED") {
		t.Fatalf("bob is still reachable from alice's segment; this is not T3: %q", probe)
	}

	// The relay client synced its allow-list at startup, when neither node had a
	// contact yet. Restart both so each re-sends one that now names the other.
	for _, n := range []*Owned{alice, bob} {
		if _, err := f.Raw(ctx, "docker", "restart", n.Node.Name); err != nil {
			t.Fatal(err)
		}
		if err := waitHealthyC(ctx, f, n.Node); err != nil {
			t.Fatalf("%s did not come back: %v", n.Node.Name, err)
		}
		if _, err := f.Raw(ctx, "docker", "restart", n.Bridge.Name); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(5 * time.Second)
	// A restart ends the owner MCP session; reattach with the same token rather
	// than re-running the passkey ceremony, which would mint a second owner.
	for _, n := range []*Owned{alice, bob} {
		if err := n.Reconnect(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Each side must still reach the relay — that is the ONLY path left, so a
	// failure here would make the delivery assertion below meaningless.
	for name, seg := range map[string]*fabric.Network{"alice": segA, "bob": segB} {
		out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", seg.Name,
			alpineImage, "sh", "-c",
			"nc -z -w3 "+relay.Name+" 8443 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
		if !strings.Contains(string(out), "REACHED") {
			t.Fatalf("%s's segment cannot reach the relay, so no path is left at all: %s", name, out)
		}
	}
	for _, n := range []*Owned{alice, bob} {
		lg, _ := f.Raw(ctx, "docker", "logs", n.Node.Name)
		if strings.Contains(string(lg), "allow-list sync") {
			var hits []string
			for _, line := range strings.Split(string(lg), "\n") {
				if strings.Contains(line, "allow-list sync") {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
			t.Fatalf("%s could not register its allow-list with the relay:\n  %s",
				n.Node.Name, strings.Join(hits, "\n  "))
		}
	}

	// --- the message: no direct path exists, so only the relay can carry it ---
	body := "queued while you were dark " + PlaintextCanary
	if _, err := alice.Owner.Call(ctx, "send_to_contact", map[string]any{
		"account_id": alice.AccountID, "contact_fpr": bob.Fpr,
		"text": body, "msg_id": "relay-1",
	}); err != nil {
		t.Fatalf("send_to_contact: %v", err)
	}
	if err := waitInbox(ctx, bob, PlaintextCanary, 3*time.Minute); err != nil {
		t.Fatalf("the message never reached bob: %v\n%s\n%s\n%s\nalice's audit: %s",
			err,
			relayLines(ctx, f, alice.Node.Name, "alice"),
			relayLines(ctx, f, relay.Name, "relay"),
			relayLines(ctx, f, bob.Node.Name, "bob"),
			auditRelay(ctx, t, alice, "alice")+"\n"+auditRelay(ctx, t, bob, "bob"))
	}

	// --- and the relay carried ciphertext, not a message ---
	rlogs, _ := f.Raw(ctx, "docker", "logs", relay.Name)
	if strings.Contains(string(rlogs), PlaintextCanary) {
		t.Errorf("the relay saw the plaintext body; §10.1 says it carries ciphertext "+
			"and metadata only:\n%s", shorten(string(rlogs), 600))
	}
	t.Log("T3: neither side reachable, contact established by the owner reaching out, " +
		"message delivered through the relay, and the relay never saw the plaintext")
}

// execOwner calls an owner tool and returns its raw text, failing the test on error.
func execOwner(ctx context.Context, t *testing.T, o *Owned, tool string, args map[string]any) string {
	t.Helper()
	raw, err := o.Owner.Call(ctx, tool, args)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return raw
}

// waitInbox polls a node's inbox until a message body shows up.
func waitInbox(ctx context.Context, o *Owned, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for {
		raw, err := o.Owner.Call(ctx, "get_inbox", map[string]any{"account_id": o.AccountID})
		if err == nil {
			last = raw
			if strings.Contains(raw, want) {
				return nil
			}
			// get_inbox lists thread summaries; the body lives in the thread.
			var threads []struct {
				ThreadID string `json:"thread_id"`
			}
			_ = json.Unmarshal([]byte(raw), &threads)
			for _, th := range threads {
				body, err := o.Owner.Call(ctx, "read_thread", map[string]any{
					"account_id": o.AccountID, "thread_id": th.ThreadID})
				if err == nil && strings.Contains(body, want) {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("inbox never carried it (last: %s)", shorten(last, 300))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// relayLines pulls just the relay-related lines out of a container's log, since
// the interesting event is one line in a wall of startup banner.
func relayLines(ctx context.Context, f *fabric.Fabric, container, label string) string {
	raw, _ := f.Raw(ctx, "docker", "logs", container)
	var hits []string
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "relay") || strings.Contains(l, "queue") ||
			strings.Contains(l, "fetch") || strings.Contains(l, "allow-list") {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	if len(hits) == 0 {
		return label + ": (nothing about the relay in its log)"
	}
	if len(hits) > 12 {
		hits = hits[len(hits)-12:]
	}
	return label + ":\n  " + strings.Join(hits, "\n  ")
}

// auditRelay pulls the relay-related audit rows, which is where the relay client
// records itself — those events go to the hash chain, not to stdout, so a log
// with nothing about the relay in it says nothing either way.
func auditRelay(ctx context.Context, t *testing.T, o *Owned, label string) string {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "audit_query", map[string]any{"limit": 200})
	if err != nil {
		return label + " audit: " + err.Error()
	}
	var rows []struct{ Action, Resource, Outcome string }
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return label + " audit: unreadable"
	}
	var hits []string
	for _, r := range rows {
		a := strings.ToLower(r.Action)
		if strings.Contains(a, "relay") || strings.Contains(a, "deliver") ||
			strings.Contains(a, "send") || strings.Contains(a, "queue") {
			hits = append(hits, r.Action+" "+r.Resource+" -> "+r.Outcome)
		}
	}
	// Everything after the fetch matters too: an envelope that arrives and then
	// fails to open leaves no relay-shaped event at all.
	tail := rows
	if len(tail) > 14 {
		tail = tail[len(tail)-14:]
	}
	for _, r := range tail {
		hits = append(hits, "· "+r.Action+" "+r.Resource+" -> "+r.Outcome)
	}
	if len(hits) == 0 {
		return label + " audit: no events at all"
	}
	return label + " audit:\n  " + strings.Join(hits, "\n  ")
}
