package scenario

// Bringing one node from "just started" to "its owner's agent can drive it":
// register the first passkey through a real browser, mint a bearer token over the
// admin socket, and connect to the owner MCP.
//
// Extracted from SetupPaired because a scenario with TWO owners needs it twice,
// and two copies of a ceremony this fiddly would drift.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/owner"
	"github.com/tech-sumit/pact-gateway/harness/portal"
	"github.com/tech-sumit/pact-gateway/harness/wallet"
)

// Owned is one node whose owner surface is reachable.
type Owned struct {
	Node      *fabric.Container
	Bridge    *fabric.Container
	Owner     *owner.Client
	AccountID string
	// Fpr is this identity: the fingerprint of its owner's ROOT, which is what another node pins
	// it by (PACT §2). It was the account key's, from `account create`, while the key was the
	// identity.
	Fpr string
	// Wallet is that owner's root, kept so a scenario can do what only an owner can: renew the
	// leaf, or move the identity to another address.
	Wallet *wallet.Wallet
	// Pin is what a caller holds of this node: the root, the leaf it serves under, the address.
	Pin wallet.Pin
	// Portal is the owner's signed-in session, for what only the portal does (settings) and for
	// reading what the page reads.
	Portal    *OwnerSession
	OwnerPort string
	// Token is kept so the owner surface can be re-connected after a restart:
	// the MCP session does not survive one, and re-running the passkey ceremony
	// would mint a second owner rather than reattach to the first.
	Token string
}

// Reconnect re-establishes the owner MCP session, which a container restart ends.
func (o *Owned) Reconnect(ctx context.Context) error {
	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+o.OwnerPort+"/owner/mcp", o.Token)
	if err != nil {
		return fmt.Errorf("reconnecting to %s: %w", o.Node.Name, err)
	}
	o.Owner = oc
	return nil
}

// BootstrapOwner registers the first passkey and returns a connected owner client.
// ownerPort is the HOST port the node's portal is published on — the browser runs
// on the host, so the portal has to be reachable from there, and it must be
// `localhost` rather than an IP because an IP is not a valid WebAuthn RP ID.
func BootstrapOwner(ctx context.Context, f *fabric.Fabric, node *fabric.Container, ownerPort string) (*owner.Client, string, *OwnerSession, error) {
	tok, err := setupTok(ctx, f, node)
	if err != nil {
		return nil, "", nil, err
	}
	br, err := portal.Open(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("chrome: %w", err)
	}
	defer br.Close()
	base := "http://localhost:" + ownerPort
	if _, err := br.RegisterFirstPasskey(ctx, base+"/setup?token="+tok, "harness"); err != nil {
		return nil, "", nil, fmt.Errorf("wizard: %w", err)
	}
	// The ceremony leaves the browser signed in. Its cookies are the owner's session, and they
	// outlive the browser: everything after this is plain HTTP as that owner.
	cookies, err := br.Cookies(ctx, base+"/")
	if err != nil {
		return nil, "", nil, err
	}
	session := &OwnerSession{Base: base, cookies: cookies}
	if session.csrf() == "" {
		return nil, "", nil, fmt.Errorf("the browser holds no pact_csrf cookie for %s after registering a passkey: %d cookie(s)", base, len(cookies))
	}
	ownerID := strings.TrimPrefix(field(execS(ctx, f, node, "/pact-gateway", "passkey", "list"), "owner="), "owner=")
	if ownerID == "" {
		return nil, "", nil, fmt.Errorf("no owner id after registering a passkey")
	}
	token := ""
	for _, l := range strings.Split(execS(ctx, f, node,
		"/pact-gateway", "token", "create", "-owner", ownerID, "-label", "harness"), "\n") {
		if strings.Contains(l, "shown once") {
			token = strings.TrimSpace(l[strings.LastIndex(l, ":")+1:])
		}
	}
	if token == "" {
		return nil, "", nil, fmt.Errorf("no owner token")
	}
	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+ownerPort+"/owner/mcp", token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("owner mcp: %w", err)
	}
	return oc, token, session, nil
}

// StartOwnedNode brings up a node with its portal published, an account created and CERTIFIED
// by its owner's wallet — until which it is nobody, and serves nothing — and its owner surface
// connected. publicURL is the address the leaf will name, so it is a name other nodes on the
// network can dial and never a loopback address, which no wallet issues for.
//
// `aliases` are extra names the node answers to on its network: the address a scenario MOVES the
// identity to has to resolve before anybody is told of it.
func StartOwnedNode(ctx context.Context, f *fabric.Fabric, image string, net *fabric.Network,
	slug, ownerPort, publicURL string, extraEnv map[string]string, aliases ...string) (*Owned, error) {

	env := map[string]string{
		"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
		"PACT_PUBLIC_URL":    publicURL,
		"PACT_INTERNAL_BIND": "127.0.0.1:8080",
		"PACT_CLIENT_CERT":   "preferred",
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	node, err := f.Container(ctx, fabric.Spec{
		Name: slug, Image: image, Network: net, Env: env, Aliases: aliases,
		Ports: []string{ownerPort + ":8081"},
		Cmd:   []string{"serve"},
	})
	if err != nil {
		return nil, err
	}
	out := &Owned{Node: node, OwnerPort: ownerPort}
	if err := waitHealthyC(ctx, f, node); err != nil {
		return out, err
	}
	name := strings.ToUpper(slug[:1]) + slug[1:]
	if acct, err := f.Exec(ctx, node, "/pact-gateway", "account", "create", "--slug", slug, "--name", name); err != nil {
		return out, fmt.Errorf("account create on %s: %w (%s)", slug, err, acct)
	}
	if out.Wallet, err = wallet.New(name); err != nil {
		return out, err
	}
	if out.Pin, err = out.Wallet.Certify(ctx, wallet.Docker(node.Name), slug, "", ""); err != nil {
		return out, err
	}
	out.Fpr = out.Pin.Root
	// The portal is loopback-bound (SPEC §8.3); a sidecar in the node's own
	// namespace publishes it without the node binding non-loopback.
	bridge, err := f.Container(ctx, fabric.Spec{
		Name: slug + "-bridge", Image: socatImage, NetworkMode: "container:" + node.Name,
		Cmd: []string{"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"},
	})
	if err != nil {
		return out, err
	}
	out.Bridge = bridge
	time.Sleep(2 * time.Second)

	oc, token, session, err := BootstrapOwner(ctx, f, node, ownerPort)
	if err != nil {
		return out, err
	}
	out.Owner, out.Token, out.Portal = oc, token, session
	accts, err := oc.Accounts(ctx)
	if err != nil || len(accts) != 1 {
		return out, fmt.Errorf("list_accounts on %s gave %v (%v)", slug, accts, err)
	}
	out.AccountID = accts[0]
	return out, nil
}
