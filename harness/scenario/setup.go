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
	"github.com/tech-sumit/pact-gateway/harness/wallet"
)

// Paired is a standing node with one approved contact.
type Paired struct {
	Fab       *fabric.Fabric
	Net       *fabric.Network
	Node      *fabric.Container
	Bridge    *fabric.Container
	Owner     *owner.Client
	AccountID string
	// Wallet is the node owner's root: the identity, which the node never holds (PACT §2).
	Wallet *wallet.Wallet
	// Portal is the owner's signed-in portal session (SPEC §8.3: every bind requires one).
	Portal    *OwnerSession
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
			"PACT_PUBLIC_BIND": "0.0.0.0:8443",
			// A NAME: the leaf names this address, and no wallet issues one for loopback (PACT
			// §14.2 rule 5). The contact's agent dials it to the published port (Target.Dial).
			"PACT_PUBLIC_URL":    "https://alice.harness.example:" + p.Public,
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

	if acct, err := f.Exec(ctx, node, "/pact-gateway", "account", "create", "--slug", "alice", "--name", "Alice"); err != nil {
		return out, fmt.Errorf("account create: %w (%s)", err, acct)
	}
	// Certified by its owner's wallet, without which the account is nobody and serves nothing.
	if out.Wallet, err = wallet.New("Alice"); err != nil {
		return out, err
	}
	pin, err := out.Wallet.Certify(ctx, wallet.Docker(node.Name), "alice", "", "")
	if err != nil {
		return out, err
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

	// The same ceremony every owned node goes through: a passkey in a real browser, a bearer
	// token over the admin socket, the owner MCP, and the signed-in portal session.
	oc, _, session, err := BootstrapOwner(ctx, f, node, p.Owner)
	if err != nil {
		return out, err
	}
	out.Owner, out.Portal = oc, session

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
	out.Target = peer.Target{Endpoint: pin.Endpoint, Dial: "127.0.0.1:" + p.Public, Root: pin.Root, Leaf: pin.Leaf}
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
