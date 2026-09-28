package scenario

// The one way a scenario stands up an OWNED node — one with an account certified by its owner's
// wallet, a signed-in owner and the owner MCP. It was three: SetupPaired (one node and a
// contact), StartOwnedNode (a node a second owner could have too), and pairing_live_test.go's own
// copy of both, each with its own environment map, its own health wait and its own hand-picked
// ports — four of which (18680, 18681, 18691, 18692) were claimed by two scenarios each. Now a
// scenario begins with `begin`, which registers it and gives it a World, and asks the World for
// nodes. What is not an owned node is built otherwise: T5's ingress role and T6's frps are
// plain fabric containers, the fabric tests (F1-F5) build through fabric and topology, and T7
// adopts containers the Cloudflare demo script built.

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/owner"
	"github.com/pact-cloud/pact-gateway/harness/peer"
	"github.com/pact-cloud/pact-gateway/harness/portal"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
	"github.com/pact-cloud/pact-gateway/harness/wallet"
)

// ArtifactsEnv names a directory each scenario's container logs are collected into at teardown
// (and the portal scenario's screenshots).
const ArtifactsEnv = "PACT_HARNESS_ARTIFACTS"

// World is everything one scenario builds: a fabric namespaced by the scenario's id and this
// run, and the nodes it asked for. It is torn down when the test ends.
type World struct {
	Fab   *fabric.Fabric
	owned []*Owned
}

// begin registers a scenario (registry.Start: needs, timeout, verdict) and gives it a World.
func begin(t *testing.T, s registry.Spec) (context.Context, *World) {
	t.Helper()
	ctx := registry.Start(t, s)
	w := &World{Fab: fabric.New(fabric.PrefixFor(s.ID), fabric.Local)}
	t.Cleanup(w.teardown)
	return ctx, w
}

func (w *World) teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, o := range w.owned {
		if o.Owner != nil {
			_ = o.Owner.Close()
		}
	}
	if dir := os.Getenv(ArtifactsEnv); dir != "" {
		_ = w.Fab.Collect(ctx, dir)
	}
	_ = w.Fab.Teardown(ctx)
}

// LAN is one ordinary network for the scenario's nodes.
func (w *World) LAN(ctx context.Context) (*fabric.Network, error) {
	return w.Fab.Network(ctx, "lan", fabric.NetOpts{})
}

// NodeOpts describes one node.
type NodeOpts struct {
	// Slug is the account the node serves and the container's short name.
	Slug string
	// Image is images.Node when empty.
	Image string
	Net   *fabric.Network
	// PublicURL is the address the account's leaf names. By default it is the container's own
	// name on its network, https://<container>:8443.
	PublicURL string
	// PublishPublic also publishes the public surface to a free host port, for an agent that
	// runs in the test process itself. PublicURL then defaults to
	// https://<slug>.harness.example:<port> — a NAME, because no wallet issues a leaf for a
	// loopback address (PACT §14.2 rule 5); the agent dials it to the published port
	// (peer.Target.Dial), which is DNS's job for a real caller.
	PublishPublic bool
	// Env is added to topology.NodeEnv, and wins where they overlap.
	Env map[string]string
	// Aliases are extra names the node answers to on its network: the address a scenario MOVES
	// an identity to has to resolve before anybody is told of it.
	Aliases []string
	// DNS replaces the resolvers the container forwards to (fabric.Spec.DNS).
	DNS []string
	// LeafUntil is when the account's first leaf expires; zero is a year.
	LeafUntil time.Time
}

// Owned is one node whose owner surface is reachable.
type Owned struct {
	Node   *fabric.Container
	Bridge *fabric.Container
	Owner  *owner.Client
	// AccountID is the one account the owner administers.
	AccountID string
	// Fpr is this identity: the fingerprint of its owner's ROOT, which is what another node pins
	// it by (PACT §2).
	Fpr string
	// Wallet is that owner's root, kept so a scenario can do what only an owner can: renew the
	// leaf, or move the identity to another address.
	Wallet *wallet.Wallet
	// Pin is what a caller holds of this node: the root, the leaf it serves under, the address.
	Pin wallet.Pin
	// Portal is the owner's signed-in session, for what only the portal does (settings) and for
	// reading what the page reads.
	Portal *OwnerSession
	// OwnerPort is the host port the portal and owner MCP are published on; PublicPort the one
	// the public surface is, when PublishPublic asked for it.
	OwnerPort, PublicPort string
}

// Node brings up a node, creates its account and has the owner's wallet CERTIFY it — until which
// it is nobody and serves nothing — publishes its loopback-bound owner surface through a sidecar,
// runs the passkey ceremony in a real browser, and connects the owner MCP. It returns as soon as
// something fails, with what it has built so far; the World tears it down either way.
func (w *World) Node(ctx context.Context, o NodeOpts) (*Owned, error) {
	ownerPort, err := fabric.FreePort()
	if err != nil {
		return nil, err
	}
	out := &Owned{OwnerPort: ownerPort}
	w.owned = append(w.owned, out)
	ports := []string{ownerPort + ":" + fmt.Sprint(bridgePort)}
	publicURL := o.PublicURL
	if o.PublishPublic {
		if out.PublicPort, err = fabric.FreePort(); err != nil {
			return out, err
		}
		ports = append(ports, out.PublicPort+":"+fmt.Sprint(topology.PublicPort))
		publicURL = cmp.Or(publicURL, "https://"+o.Slug+".harness.example:"+out.PublicPort)
	}
	publicURL = cmp.Or(publicURL, fmt.Sprintf("https://%s:%d", w.Fab.Name(o.Slug), topology.PublicPort))
	env := topology.NodeEnv(publicURL)
	maps.Copy(env, o.Env)

	if out.Node, err = w.Fab.Container(ctx, fabric.Spec{
		Name: o.Slug, Image: cmp.Or(o.Image, images.Node), Network: o.Net, Env: env,
		Aliases: o.Aliases, DNS: o.DNS, Ports: ports, Cmd: []string{"serve"},
	}); err != nil {
		return out, err
	}
	if err := topology.WaitHealthy(ctx, w.Fab, out.Node); err != nil {
		return out, err
	}
	if out.Wallet, out.Pin, err = topology.CertifyUntil(ctx, w.Fab, out.Node, o.Slug, o.LeafUntil); err != nil {
		return out, err
	}
	out.Fpr = out.Pin.Root
	if out.Bridge, err = w.Bridge(ctx, out.Node); err != nil {
		return out, err
	}
	if err := waitPortal(ctx, ownerPort); err != nil {
		return out, err
	}
	if out.Owner, out.Portal, err = BootstrapOwner(ctx, w.Fab, out.Node, ownerPort); err != nil {
		return out, err
	}
	accts, err := out.Owner.Accounts(ctx)
	if err != nil || len(accts) != 1 {
		return out, fmt.Errorf("list_accounts on %s gave %v (%v)", o.Slug, accts, err)
	}
	out.AccountID = accts[0]
	return out, nil
}

// bridgePort is where the sidecar listens in the node's namespace, forwarding to the owner
// surface on loopback.
const bridgePort = 8081

// Bridge starts the sidecar that publishes a node's owner surface. The surface is loopback-bound
// (SPEC §8.3); a socat in the node's own network namespace reaches it without the node binding
// non-loopback. A node restart takes the namespace with it, so a scenario that restarts a node
// restarts its bridge too.
func (w *World) Bridge(ctx context.Context, node *fabric.Container) (*fabric.Container, error) {
	short := strings.TrimPrefix(node.Name, w.Fab.Prefix()+"-")
	return w.Fab.Container(ctx, fabric.Spec{
		Name: short + "-bridge", Image: images.Socat, NetworkMode: "container:" + node.Name,
		Cmd: []string{fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", bridgePort),
			fmt.Sprintf("TCP:127.0.0.1:%d", topology.InternalPort)},
	})
}

// waitPortal polls the published owner surface until something answers HTTP through the
// bridge. It replaces a fixed two-second sleep after starting the bridge.
func waitPortal(ctx context.Context, hostPort string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	var last error
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+hostPort+"/", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("the owner surface on host port %s never answered: %v", hostPort, last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// BootstrapOwner registers the first passkey and returns a connected owner client and the
// signed-in portal session. ownerPort is the HOST port the portal is published on:
// the browser runs on the host, so the portal has to be reachable from there, and it must be
// `localhost` rather than an IP because an IP is not a valid WebAuthn RP ID.
func BootstrapOwner(ctx context.Context, f *fabric.Fabric, node *fabric.Container, ownerPort string) (*owner.Client, *OwnerSession, error) {
	tok, err := setupToken(ctx, f, node)
	if err != nil {
		return nil, nil, err
	}
	br, err := portal.Open(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("chrome: %w", err)
	}
	defer br.Close()
	base := "http://localhost:" + ownerPort
	if _, err := br.RegisterFirstPasskey(ctx, base+"/setup?token="+tok, "harness"); err != nil {
		return nil, nil, fmt.Errorf("wizard: %w", err)
	}
	// The ceremony leaves the browser signed in. Its cookies are the owner's session, and they
	// outlive the browser: everything after this is plain HTTP as that owner.
	cookies, err := br.Cookies(ctx, base+"/")
	if err != nil {
		return nil, nil, err
	}
	session := &OwnerSession{Base: base, cookies: cookies}
	if session.csrf() == "" {
		return nil, nil, fmt.Errorf("the browser holds no pact_csrf cookie for %s after registering a passkey: %d cookie(s)", base, len(cookies))
	}
	token, err := OwnerToken(ctx, f, node, "harness")
	if err != nil {
		return nil, nil, err
	}
	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+ownerPort+"/owner/mcp", token)
	if err != nil {
		return nil, nil, fmt.Errorf("owner mcp: %w", err)
	}
	return oc, session, nil
}

// OwnerToken mints a bearer token for the node's owner (`token create`), as the owner's agent is
// given one, and returns it. The owner is the one whose passkey the wizard registered.
func OwnerToken(ctx context.Context, f *fabric.Fabric, node *fabric.Container, label string) (string, error) {
	ownerID := strings.TrimPrefix(field(execS(ctx, f, node, "/pact-gateway", "passkey", "list"), "owner="), "owner=")
	if ownerID == "" {
		return "", fmt.Errorf("no owner id: no passkey is registered on %s", node.Name)
	}
	for _, l := range strings.Split(execS(ctx, f, node,
		"/pact-gateway", "token", "create", "-owner", ownerID, "-label", label), "\n") {
		if strings.Contains(l, "shown once") {
			return strings.TrimSpace(l[strings.LastIndex(l, ":")+1:]), nil
		}
	}
	return "", fmt.Errorf("no owner token from %s", node.Name)
}

// Paired is a standing node with one approved contact: the node's owner, and a contact's agent
// that dials the node's public surface from the test process.
type Paired struct {
	*Owned
	Fab     *fabric.Fabric
	Net     *fabric.Network
	Contact *peer.Agent
	Target  peer.Target
}

// Paired builds a node (image: images.Node when empty) with sealing OPTIONAL — a guest cannot seal
// to a key it has not received, and receiving it is what redemption does (SPEC §9.2) — and a
// contact, bob, who redeems an invite and is approved as a friend.
func (w *World) Paired(ctx context.Context, image string) (*Paired, error) {
	net, err := w.LAN(ctx)
	if err != nil {
		return nil, err
	}
	alice, err := w.Node(ctx, NodeOpts{
		Slug: "alice", Image: image, Net: net, PublishPublic: true,
		Env: map[string]string{"PACT_SEAL": "optional"},
	})
	p := &Paired{Owned: alice, Fab: w.Fab, Net: net}
	if err != nil {
		return p, err
	}
	p.Contact, p.Target, err = w.Contact(ctx, alice)
	return p, err
}

// Contact is bob, an agent in the test process who redeems an invite from a node published with
// PublishPublic and is approved as a friend. The target is how he reaches it.
func (w *World) Contact(ctx context.Context, o *Owned) (*peer.Agent, peer.Target, error) {
	target := o.Target()
	token, err := invite(ctx, o, "harness", 1)
	if err != nil {
		return nil, target, err
	}
	bob, err := peer.NewAgent("bob")
	if err != nil {
		return nil, target, err
	}
	// The card IS the leaf certificate (PACT §3): the address is inside it, and it has to be one
	// §14.2 rule 5 allows.
	if _, err := bob.Call(ctx, target, "redeem_invite",
		map[string]any{"token": token, "card": bob.Card("optional")}, "redeem-1"); err != nil {
		return bob, target, fmt.Errorf("redeem_invite: %w", err)
	}
	if _, err := o.Owner.Call(ctx, "approve_contact", map[string]any{
		"account_id": o.AccountID, "contact_fpr": bob.Fingerprint(), "preset": "friend",
	}); err != nil {
		return bob, target, fmt.Errorf("approve_contact: %w", err)
	}
	return bob, target, nil
}

// Target is how an agent in the test process reaches a node published with PublishPublic.
func (o *Owned) Target() peer.Target {
	return peer.Target{Endpoint: o.Pin.Endpoint, Dial: "127.0.0.1:" + o.PublicPort, Root: o.Pin.Root, Leaf: o.Pin.Leaf}
}

// invite has the owner mint an invite and returns its token.
func invite(ctx context.Context, o *Owned, label string, maxUses int) (string, error) {
	raw, err := o.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": o.AccountID, "label": label, "max_uses": maxUses,
	})
	if err != nil {
		return "", fmt.Errorf("create_invite: %w", err)
	}
	var inv struct{ URL string }
	_ = json.Unmarshal([]byte(raw), &inv)
	i := strings.LastIndex(inv.URL, "/i/")
	if i < 0 || inv.URL[i+3:] == "" {
		return "", fmt.Errorf("create_invite answered no link: %s", raw)
	}
	return inv.URL[i+3:], nil
}

// shorten folds whitespace and cuts s to n bytes, for a readable failure message.
func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// field is the first whitespace-separated word of out that starts with prefix.
func field(out, prefix string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, prefix) {
			return f
		}
	}
	return ""
}

// execS runs a command in a container and returns what it printed, error or not.
func execS(ctx context.Context, f *fabric.Fabric, c *fabric.Container, args ...string) string {
	out, _ := f.Exec(ctx, c, args...)
	return string(out)
}

// setupToken reads the first-run setup token a node prints to its log.
func setupToken(ctx context.Context, f *fabric.Fabric, c *fabric.Container) (string, error) {
	out, err := f.Raw(ctx, "docker", "logs", c.Name)
	if err != nil {
		return "", err
	}
	for _, fl := range strings.Fields(string(out)) {
		if i := strings.Index(fl, "token="); i >= 0 {
			return fl[i+6:], nil
		}
	}
	return "", fmt.Errorf("no setup token in the logs of %s", c.Name)
}
