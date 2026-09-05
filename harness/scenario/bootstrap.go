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
)

// Owned is one node whose owner surface is reachable.
type Owned struct {
	Node      *fabric.Container
	Bridge    *fabric.Container
	Owner     *owner.Client
	AccountID string
	Fpr       string
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
func BootstrapOwner(ctx context.Context, f *fabric.Fabric, node *fabric.Container, ownerPort string) (*owner.Client, string, error) {
	tok, err := setupTok(ctx, f, node)
	if err != nil {
		return nil, "", err
	}
	br, err := portal.Open(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("chrome: %w", err)
	}
	defer br.Close()
	if _, err := br.RegisterFirstPasskey(ctx,
		fmt.Sprintf("http://localhost:%s/setup?token=%s", ownerPort, tok), "harness"); err != nil {
		return nil, "", fmt.Errorf("wizard: %w", err)
	}
	ownerID := strings.TrimPrefix(field(execS(ctx, f, node, "/pact-gateway", "passkey", "list"), "owner="), "owner=")
	if ownerID == "" {
		return nil, "", fmt.Errorf("no owner id after registering a passkey")
	}
	token := ""
	for _, l := range strings.Split(execS(ctx, f, node,
		"/pact-gateway", "token", "create", "-owner", ownerID, "-label", "harness"), "\n") {
		if strings.Contains(l, "shown once") {
			token = strings.TrimSpace(l[strings.LastIndex(l, ":")+1:])
		}
	}
	if token == "" {
		return nil, "", fmt.Errorf("no owner token")
	}
	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+ownerPort+"/owner/mcp", token)
	if err != nil {
		return nil, "", fmt.Errorf("owner mcp: %w", err)
	}
	return oc, token, nil
}

// StartOwnedNode brings up a node with its portal published, an account created,
// and its owner surface connected.
func StartOwnedNode(ctx context.Context, f *fabric.Fabric, image string, net *fabric.Network,
	slug, ownerPort, publicURL string, extraEnv map[string]string) (*Owned, error) {

	env := map[string]string{
		"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
		"PACT_INTERNAL_BIND": "127.0.0.1:8080",
		"PACT_CLIENT_CERT":   "preferred",
	}
	// An empty publicURL is meaningful, not missing: a relay-assisted node
	// publishes NO endpoint, and its card then carries only X-PACT-GATEWAY
	// (SPEC §9.3, §10.1). Setting the variable to "" would look the same to the
	// config loader but says something different here, so it is omitted.
	if publicURL != "" {
		env["PACT_PUBLIC_URL"] = publicURL
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	node, err := f.Container(ctx, fabric.Spec{
		Name: slug, Image: image, Network: net, Env: env,
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
	acct, err := f.Exec(ctx, node, "/pact-gateway", "account", "create",
		"--slug", slug, "--name", strings.ToUpper(slug[:1])+slug[1:])
	if err != nil {
		return out, fmt.Errorf("account create on %s: %w (%s)", slug, err, acct)
	}
	out.Fpr = field(string(acct), "sha256:")
	if out.Fpr == "" {
		return out, fmt.Errorf("%s created an account with no fingerprint", slug)
	}
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

	oc, token, err := BootstrapOwner(ctx, f, node, ownerPort)
	if err != nil {
		return out, err
	}
	out.Owner, out.Token = oc, token
	accts, err := oc.Accounts(ctx)
	if err != nil || len(accts) != 1 {
		return out, fmt.Errorf("list_accounts on %s gave %v (%v)", slug, accts, err)
	}
	out.AccountID = accts[0]
	return out, nil
}
