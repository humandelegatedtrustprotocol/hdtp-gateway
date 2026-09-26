package scenario

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/registry"
)

// T7 — two people, two real Cloudflare tunnels, one real domain.
//
// Every other scenario builds its own world. This one cannot: tunnels, DNS and a
// zone are the owner's account, not something a test may provision. So the owner
// runs `docs/demos/cloudflare-two-users.md` once, and this drives the flow across
// what it built — over the public internet, through Cloudflare's edge, in both
// directions.
//
// It is the only place the product meets a THIRD-PARTY edge it does not control,
// which is why it is worth the setup. Two defects fixed the same day were exactly
// this shape and could not have been caught anywhere else:
//
//	E13  edge mode defaults lan_connections off, and the connector delivers from
//	     inside the node's own netns — so the node refused its own connector.
//	E14  the MCP SDK's DNS-rebinding guard trips on loopback-local + public Host,
//	     which is precisely what a connector produces. Every call was 403.
//
// Both would pass a local test and fail here, so this asserts the whole path
// rather than the pieces.
func TestTwoUsersOverRealCloudflareTunnels(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "T7", Name: "two people over two real Cloudflare tunnels, sealed end to end", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.Chrome, registry.CF},
		Timeout: 20 * time.Minute,
	})
	domain := os.Getenv(registry.CFEnv)

	// Not a World: the containers, their names and their published owner ports (18120, 18121)
	// are the demo script's, which built them and keeps their volumes. This test adds the
	// bridges and tears nothing down.
	f := fabric.New("pactcf", fabric.Local)
	alice := &Owned{Node: &fabric.Container{Name: "pactcf-alice"}, OwnerPort: "18120",
		Fpr: mustFpr(ctx, t, f, "pactcf-alice")}
	bob := &Owned{Node: &fabric.Container{Name: "pactcf-bob"}, OwnerPort: "18121",
		Fpr: mustFpr(ctx, t, f, "pactcf-bob")}

	// Both must be in EDGE mode, or this is not testing what it claims: edge is
	// what forces seal `required` and client certificates off, because Cloudflare
	// terminates TLS and the node never sees the caller's certificate.
	for _, n := range []*Owned{alice, bob} {
		lg, _ := f.Raw(ctx, "docker", "logs", n.Node.Name)
		if !strings.Contains(string(lg), "mode=edge") {
			t.Fatalf("%s is not in edge mode:\n%s", n.Node.Name, shorten(string(lg), 300))
		}
	}

	// The portal is loopback-bound (SPEC §8.3). A sidecar in the node's namespace
	// publishes it to the host for the passkey ceremony without the node ever
	// binding non-loopback.
	for _, n := range []*Owned{alice, bob} {
		name := n.Node.Name + "-bridge"
		_, _ = f.Raw(ctx, "docker", "rm", "-f", name)
		if out, err := f.Raw(ctx, "docker", "run", "-d", "--name", name,
			"--network", "container:"+n.Node.Name, images.Socat,
			"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"); err != nil {
			t.Fatalf("portal bridge for %s: %v (%s)", n.Node.Name, err, out)
		}
		n.Bridge = &fabric.Container{Name: name}
		if err := waitPortal(ctx, n.OwnerPort); err != nil {
			t.Fatal(err)
		}
	}

	for _, n := range []*Owned{alice, bob} {
		oc, session, err := BootstrapOwner(ctx, f, n.Node, n.OwnerPort)
		if err != nil {
			t.Fatalf("bootstrapping %s: %v", n.Node.Name, err)
		}
		n.Owner, n.Portal = oc, session
		accts, err := oc.Accounts(ctx)
		if err != nil || len(accts) != 1 {
			t.Fatalf("%s: list_accounts gave %v (%v)", n.Node.Name, accts, err)
		}
		n.AccountID = accts[0]
	}

	// --- alice invites, over her real public name ---
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
		inv.URL = "https://alice." + domain + "/i/" + inv.Token
	}
	if inv.URL == "" {
		t.Fatalf("no invite token in %s", shorten(inviteRaw, 200))
	}

	// --- bob reaches out across the internet ---
	//
	// This crosses Cloudflare TWICE and is the part edge mode makes hard: bob
	// fetches alice's landing page for her card and public key, then calls
	// `redeem_invite` SEALED — edge mode forces seal `required`, and a guest
	// cannot seal to a key it has not been given. The landing page handing over
	// the SPKI (§9.2) is exactly what makes a sealed first contact possible.
	addRaw, err := bob.Owner.Call(ctx, "add_contact", map[string]any{
		"account_id": bob.AccountID, "invite_url": inv.URL,
	})
	if err != nil {
		t.Fatalf("add_contact: %v", err)
	}
	var added struct{ Fingerprint, Status, Code, Detail string }
	_ = json.Unmarshal([]byte(addRaw), &added)
	if added.Code != "" {
		t.Fatalf("add_contact refused: %s — %s", added.Code, added.Detail)
	}
	if added.Fingerprint != alice.Fpr {
		t.Fatalf("bob pinned %q, want alice's %q", added.Fingerprint, alice.Fpr)
	}
	t.Logf("bob pinned alice as %s (%s) across the public internet", added.Fingerprint, added.Status)

	// Alice decides what bob may do on HER node; redeeming granted him nothing.
	if _, err := alice.Owner.Call(ctx, "set_permissions", map[string]any{
		"account_id": alice.AccountID, "contact_fpr": bob.Fpr,
		"permissions": []string{"message.text"},
	}); err != nil {
		t.Fatalf("granting bob message.text: %v", err)
	}

	// --- and a message, edge to edge ---
	body := "hello across the internet " + PlaintextCanary
	if _, err := bob.Owner.Call(ctx, "send_to_contact", map[string]any{
		"account_id": bob.AccountID, "contact_fpr": alice.Fpr,
		"text": body, "msg_id": "cf-1",
	}); err != nil {
		t.Fatalf("send_to_contact: %v", err)
	}
	if err := waitInbox(ctx, alice, PlaintextCanary, 3*time.Minute); err != nil {
		t.Fatalf("the message never reached alice: %v\n%s\n%s",
			err, auditDelivery(ctx, t, bob, "bob"), auditDelivery(ctx, t, alice, "alice"))
	}

	// The edge saw ciphertext. Cloudflare terminated TLS, so the envelope is the
	// only thing that kept the body from it — that is the whole claim of §10.
	for _, n := range []*Owned{alice, bob} {
		lg, _ := f.Raw(ctx, "docker", "logs", n.Node.Name+"-cfd")
		if strings.Contains(string(lg), PlaintextCanary) {
			t.Errorf("%s's connector logged the plaintext body", n.Node.Name)
		}
	}
	t.Logf("T7: bob → alice through two Cloudflare tunnels on %s, sealed end to end", domain)
}

// mustFpr reads an account's fingerprint from a node that already has one.
// mustFpr is the identity a contact pins: the node's ROOT fingerprint.
//
// It used to read `account list`, whose fingerprint column is the account's own
// KEY. That was the identity in 1.x; it is the leaf key now and changes at every
// renewal, so it is `account certificate` that answers the question — and a node
// with no leaf yet has no identity to pin at all, which this says plainly rather
// than handing back a key that pins nothing.
func mustFpr(ctx context.Context, t *testing.T, f *fabric.Fabric, container string) string {
	t.Helper()
	out, err := f.Raw(ctx, "docker", "exec", container, "/pact-gateway", "account", "certificate", "-slug", slugOf(container))
	if err != nil {
		t.Fatalf("account certificate on %s: %v (%s)", container, err, out)
	}
	root := field(string(out), "sha256:")
	if root == "" {
		t.Fatalf("%s has no certificate yet — it needs a leaf from its wallet before it has an identity to pin: %s",
			container, shorten(string(out), 200))
	}
	return root
}

// slugOf is the account slug a harness container serves: the last dash-separated
// word of its name, which is how every scenario names them (pactcf-alice → alice).
func slugOf(container string) string {
	if i := strings.LastIndex(container, "-"); i >= 0 {
		return container[i+1:]
	}
	return container
}
