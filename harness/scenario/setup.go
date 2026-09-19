package scenario

// Shared setup for live scenarios: one node, paired with one contact, reached
// through every surface the product really has.
//
// It is a package-level helper rather than a test helper because several
// scenarios need the same starting state, and each one rebuilding it by hand is
// how two scenarios quietly end up testing different things.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/owner"
	"github.com/tech-sumit/pact-gateway/harness/peer"
	"github.com/tech-sumit/pact-gateway/harness/portal"
)

// Paired is a standing node with one approved contact.
type Paired struct {
	Fab       *fabric.Fabric
	Net       *fabric.Network
	Node      *fabric.Container
	Bridge    *fabric.Container
	Owner     *owner.Client
	AccountID string
	NodeFpr   string
	Contact   *peer.Agent
	Target    peer.Target
	OwnerPort string
}

// Ports lets each scenario claim its own host ports, so two can run at once.
type Ports struct{ Owner, Public string }

func dockerRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// SetupPaired builds the whole chain and returns it ready to exercise.
func SetupPaired(ctx context.Context, prefix string, p Ports, image string) (*Paired, error) {
	f := fabric.New(prefix, dockerRun)
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		return nil, err
	}
	node, err := f.Container(ctx, fabric.Spec{
		Name: "node", Image: image, Network: net,
		Ports: []string{p.Owner + ":8081", p.Public + ":8443"},
		Env: map[string]string{
			"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
			"PACT_PUBLIC_URL":    "https://127.0.0.1:" + p.Public,
			"PACT_INTERNAL_BIND": "127.0.0.1:8080",
			"PACT_CLIENT_CERT":   "preferred",
			// Guest onboarding needs sealing OPTIONAL: a guest cannot seal to a
			// key it has not received, and receiving it is what redemption does
			// (SPEC §9.2).
			"PACT_SEAL": "optional",
		},
		Cmd: []string{"serve"},
	})
	if err != nil {
		return nil, err
	}
	out := &Paired{Fab: f, Net: net, Node: node, OwnerPort: p.Owner}
	if err := waitHealthyC(ctx, f, node); err != nil {
		return out, err
	}

	acct, err := f.Exec(ctx, node, "/pact-gateway", "account", "create", "--slug", "alice", "--name", "Alice")
	if err != nil {
		return out, fmt.Errorf("account create: %w (%s)", err, acct)
	}
	out.NodeFpr = field(string(acct), "sha256:")
	if out.NodeFpr == "" {
		return out, fmt.Errorf("no fingerprint in %q", acct)
	}

	// The internal surface is loopback-bound (§8.3); a sidecar in the node's own
	// namespace reaches it without the node binding non-loopback.
	bridge, err := f.Container(ctx, fabric.Spec{
		Name: "bridge", Image: "alpine/socat", NetworkMode: "container:" + node.Name,
		Cmd: []string{"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"},
	})
	if err != nil {
		return out, err
	}
	out.Bridge = bridge
	time.Sleep(2 * time.Second)

	tok, err := setupTok(ctx, f, node)
	if err != nil {
		return out, err
	}
	br, err := portal.Open(ctx)
	if err != nil {
		return out, fmt.Errorf("chrome: %w", err)
	}
	defer br.Close()
	// localhost, not an IP: an IP is not a valid WebAuthn RP ID and the node
	// refuses to bind credentials to one.
	if _, err := br.RegisterFirstPasskey(ctx,
		fmt.Sprintf("http://localhost:%s/setup?token=%s", p.Owner, tok), "harness"); err != nil {
		return out, fmt.Errorf("wizard: %w", err)
	}

	// No restart: P14-05a made a live-created account servable immediately, and
	// keeping the workaround would hide a regression of exactly that.

	ownerID := strings.TrimPrefix(field(execS(ctx, f, node, "/pact-gateway", "passkey", "list"), "owner="), "owner=")
	token := ""
	for _, l := range strings.Split(execS(ctx, f, node, "/pact-gateway", "token", "create", "-owner", ownerID, "-label", "harness"), "\n") {
		if strings.Contains(l, "shown once") {
			token = strings.TrimSpace(l[strings.LastIndex(l, ":")+1:])
		}
	}
	if token == "" {
		return out, fmt.Errorf("no owner token")
	}
	oc, err := owner.Connect(ctx, "http://127.0.0.1:"+p.Owner+"/owner/mcp", token)
	if err != nil {
		return out, fmt.Errorf("owner mcp: %w", err)
	}
	out.Owner = oc

	accts, err := oc.Accounts(ctx)
	if err != nil || len(accts) != 1 {
		return out, fmt.Errorf("list_accounts gave %v (%v)", accts, err)
	}
	out.AccountID = accts[0]

	inviteRaw, err := oc.Call(ctx, "create_invite", map[string]any{
		"account_id": out.AccountID, "label": "harness", "max_uses": 1,
	})
	if err != nil {
		return out, fmt.Errorf("create_invite: %w", err)
	}
	var inv struct{ Token, URL string }
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.Token == "" {
		if i := strings.LastIndex(inv.URL, "/i/"); i >= 0 {
			inv.Token = inv.URL[i+3:]
		}
	}
	if inv.Token == "" {
		return out, fmt.Errorf("no invite token in %s", inviteRaw)
	}

	bob, err := peer.NewAgent("bob")
	if err != nil {
		return out, err
	}
	out.Contact = bob
	out.Target = peer.Target{
		Endpoint: "https://127.0.0.1:" + p.Public + "/a/alice/mcp",
		Root:     out.NodeFpr,
	}
	// The card IS the leaf certificate (PACT §3). It used to be a 1.x card naming a
	// key and an address; the address is inside the certificate now, and it has to be
	// one §14.2 rule 5 allows — which `https://bob.invalid/mcp` never was.
	if _, err := bob.Call(ctx, out.Target, "redeem_invite",
		map[string]any{"token": inv.Token, "card": bob.Card("optional")}, "redeem-1"); err != nil {
		return out, fmt.Errorf("redeem_invite: %w", err)
	}
	if _, err := oc.Call(ctx, "approve_contact", map[string]any{
		"account_id": out.AccountID, "contact_fpr": bob.Fingerprint(), "preset": "friend",
	}); err != nil {
		return out, fmt.Errorf("approve_contact: %w", err)
	}
	return out, nil
}

// Teardown removes everything, collecting artifacts first when asked.
func (p *Paired) Teardown(artifactDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if p.Owner != nil {
		_ = p.Owner.Close()
	}
	if artifactDir != "" {
		_ = p.Fab.Collect(ctx, artifactDir)
	}
	_ = p.Fab.Teardown(ctx)
}

func field(out, prefix string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, prefix) {
			return f
		}
	}
	return ""
}

func execS(ctx context.Context, f *fabric.Fabric, c *fabric.Container, args ...string) string {
	out, _ := f.Exec(ctx, c, args...)
	return string(out)
}

func setupTok(ctx context.Context, f *fabric.Fabric, c *fabric.Container) (string, error) {
	out, err := f.Raw(ctx, "docker", "logs", c.Name)
	if err != nil {
		return "", err
	}
	for _, fl := range strings.Fields(string(out)) {
		if i := strings.Index(fl, "token="); i >= 0 {
			return fl[i+6:], nil
		}
	}
	return "", fmt.Errorf("no setup token in logs")
}

func waitHealthyC(ctx context.Context, f *fabric.Fabric, c *fabric.Container) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := f.Exec(ctx, c, "/pact-gateway", "healthcheck"); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s never became healthy", c.Name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}
