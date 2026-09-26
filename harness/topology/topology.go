// Package topology stands the network shapes of docs/harness-design.md §3 up as
// running pact-gateway nodes.
//
// The shapes exist to make reachability claims TRUE rather than asserted. T2 does
// not simulate a NAT by having the test decline to dial; the node genuinely sits on
// an --internal Docker network with a MASQUERADE router in front, so an inbound
// connection has nowhere to go. That is the difference between a scenario that
// tests the product and one that tests the test.
package topology

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/wallet"
)

// Kind names a topology from the design document.
type Kind string

const (
	T1LAN Kind = "T1-lan"
	T2NAT Kind = "T2-nat"
)

// PublicPort is the port every node's public surface binds inside its container.
const PublicPort = 8443

// Node is one running pact-gateway.
type Node struct {
	Name      string
	Slug      string
	Container *fabric.Container
	PublicURL string
	// Fingerprint is this node's identity: the fingerprint of its owner's ROOT, which is what
	// another node pins it by (PACT §2). Empty until Provision runs. It was the account key's,
	// read back from `account create`, while a key was an identity.
	Fingerprint string
	// Wallet is that owner's root, and Pin what a caller holds of the node once it is certified.
	Wallet *wallet.Wallet
	Pin    wallet.Pin
	// Reachable is false for a node behind a NAT: nothing outside its segment can
	// open a connection to it. Scenarios assert against this rather than guessing.
	Reachable bool
}

// Topo is a standing topology.
type Topo struct {
	Kind Kind
	Fab  *fabric.Fabric
	// Image is the node image this topology was built from. Invariants reuse it to
	// run offline CLI checks in a sidecar against a stopped node's volumes.
	Image string
	Nodes []*Node
}

// Node returns a node by slug, or nil.
func (t *Topo) Node(slug string) *Node {
	for _, n := range t.Nodes {
		if n.Slug == slug {
			return n
		}
	}
	return nil
}

// NodeEnv is the environment every harness node starts with; a scenario adds to it (PACT_SEAL,
// for one). Every knob is an environment variable because SPEC §12.2 makes env the
// highest-precedence config layer, so a node needs no config files inside the image.
//
// publicURL is the address the node's leaf will name, so it is a name other nodes can dial and
// never a loopback address, which no wallet issues a leaf for (PACT §14.2 rule 5).
func NodeEnv(publicURL string) map[string]string {
	return map[string]string{
		"PACT_PUBLIC_BIND": fmt.Sprintf("0.0.0.0:%d", PublicPort),
		"PACT_PUBLIC_URL":  publicURL,
		// The portal stays on loopback inside the container: SPEC §8.3 refuses a
		// non-loopback internal bind without auth and TLS, and the harness has no
		// business weakening that to make itself easier to drive.
		"PACT_INTERNAL_BIND": fmt.Sprintf("127.0.0.1:%d", InternalPort),
		// Asked for, not required: a guest arrives without a chain the node knows.
		"PACT_CLIENT_CERT": "preferred",
	}
}

// InternalPort is where a node's owner surface (portal, owner MCP) listens, on loopback.
const InternalPort = 8080

// nodeSpec builds the container spec for one topology node.
func nodeSpec(name, image string, net *fabric.Network, f *fabric.Fabric) fabric.Spec {
	env := NodeEnv(fmt.Sprintf("https://%s:%d", f.Name(name), PublicPort))
	return fabric.Spec{Name: name, Image: image, Network: net, Env: env, Cmd: []string{"serve"}}
}

// LAN is T1: two nodes on one segment, both dialable. The control topology — if a
// scenario fails here, the failure is not about reachability.
func LAN(ctx context.Context, f *fabric.Fabric, image string) (*Topo, error) {
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		return nil, err
	}
	t := &Topo{Kind: T1LAN, Fab: f, Image: image}
	for _, slug := range []string{"alice", "bob"} {
		c, err := f.Container(ctx, nodeSpec(slug, image, net, f))
		if err != nil {
			return nil, err
		}
		t.Nodes = append(t.Nodes, &Node{
			Name: c.Name, Slug: slug, Container: c, Reachable: true,
			PublicURL: fmt.Sprintf("https://%s:%d", c.Name, PublicPort),
		})
	}
	return t, nil
}

// BehindNAT is T2: alice is dialable, bob is not.
func BehindNAT(ctx context.Context, f *fabric.Fabric, image string) (*Topo, error) {
	wan, err := f.Network(ctx, "wan", fabric.NetOpts{})
	if err != nil {
		return nil, err
	}
	lan, err := f.Network(ctx, "lan", fabric.NetOpts{Internal: true})
	if err != nil {
		return nil, err
	}
	if _, err := f.NAT(ctx, "nat", wan, lan); err != nil {
		return nil, err
	}
	t := &Topo{Kind: T2NAT, Fab: f, Image: image}
	for _, spec := range []struct {
		slug      string
		net       *fabric.Network
		reachable bool
	}{
		{"alice", wan, true},
		{"bob", lan, false},
	} {
		c, err := f.Container(ctx, nodeSpec(spec.slug, image, spec.net, f))
		if err != nil {
			return nil, err
		}
		t.Nodes = append(t.Nodes, &Node{
			Name: c.Name, Slug: spec.slug, Container: c, Reachable: spec.reachable,
			PublicURL: fmt.Sprintf("https://%s:%d", c.Name, PublicPort),
		})
	}
	return t, nil
}

// WaitReady blocks until every node answers its own healthcheck, or the context ends.
//
// It polls rather than sleeping: a fixed sleep is either too short on a loaded
// machine (flake) or too long on an idle one (waste), and it hides how long
// startup actually took.
func (t *Topo) WaitReady(ctx context.Context) error {
	for _, n := range t.Nodes {
		if err := WaitHealthy(ctx, t.Fab, n.Container); err != nil {
			return err
		}
	}
	return nil
}

// HealthBudget bounds how long WaitHealthy waits for one node.
const HealthBudget = 90 * time.Second

// WaitHealthy polls a node's own healthcheck until it answers, HealthBudget passes, or the
// context ends. It is the one health wait for a node the harness starts with `serve`; the
// ingress role (T5) is waited for by its log line, and T7 adopts nodes already running.
func WaitHealthy(ctx context.Context, f *fabric.Fabric, c *fabric.Container) error {
	ctx, cancel := context.WithTimeout(ctx, HealthBudget)
	defer cancel()
	var last error
	for {
		if _, err := f.Exec(ctx, c, "/pact-gateway", "healthcheck"); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			logs, _ := f.Raw(context.WithoutCancel(ctx), "docker", "logs", "--tail", "40", c.Name)
			return fmt.Errorf("topology: %s never became healthy: %w (last: %v)\n%s", c.Name, ctx.Err(), last, logs)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Certify creates the account `slug` on a running node and has a new wallet — its owner's root —
// certify it. Until then the account is nobody and the node has no certificate to present
// (PACT §2). Every account the harness makes on a container node is made through here; the VM
// guest (S8) creates its own, in its boot script.
func Certify(ctx context.Context, f *fabric.Fabric, c *fabric.Container, slug string) (*wallet.Wallet, wallet.Pin, error) {
	name := strings.ToUpper(slug[:1]) + slug[1:]
	if out, err := f.Exec(ctx, c, "/pact-gateway", "account", "create", "--slug", slug, "--name", name); err != nil {
		return nil, wallet.Pin{}, fmt.Errorf("topology: creating account %s on %s: %w (%s)", slug, c.Name, err, out)
	}
	w, err := wallet.New(name)
	if err != nil {
		return nil, wallet.Pin{}, err
	}
	pin, err := w.Certify(ctx, NodeOf(f, c), slug, "", "")
	if err != nil {
		return nil, wallet.Pin{}, fmt.Errorf("topology: certifying %s on %s: %w", slug, c.Name, err)
	}
	return w, pin, nil
}

// Provision creates one account per node and has its owner's wallet certify it. What it records
// is the identity every later scenario pins against: the ROOT, and the leaf under it.
func (t *Topo) Provision(ctx context.Context) error {
	for _, n := range t.Nodes {
		w, pin, err := Certify(ctx, t.Fab, n.Container, n.Slug)
		if err != nil {
			return err
		}
		n.Wallet, n.Pin, n.Fingerprint = w, pin, pin.Root
	}
	// No restart here on purpose. The node used to load account certificates at
	// startup only, so an account created on a running node was unreachable until
	// it restarted, and this function worked around that. P14-05a fixed the node;
	// the workaround is gone so that a regression fails a scenario instead of
	// being quietly absorbed.
	return nil
}

// NodeOf is a node as a wallet reaches it: through the fabric's own runner, so a topology built
// on a recording runner provisions without a Docker daemon.
func NodeOf(f *fabric.Fabric, c *fabric.Container) wallet.Node { return fabricNode{f, c} }

type fabricNode struct {
	f *fabric.Fabric
	c *fabric.Container
}

func (n fabricNode) Exec(ctx context.Context, args ...string) ([]byte, error) {
	return n.f.Exec(ctx, n.c, append([]string{"/pact-gateway"}, args...)...)
}

func (n fabricNode) CopyIn(ctx context.Context, hostPath, nodePath string) error {
	if out, err := n.f.Raw(ctx, "docker", "cp", hostPath, n.c.Name+":"+nodePath); err != nil {
		return fmt.Errorf("docker cp into %s: %w (%s)", n.c.Name, err, out)
	}
	return nil
}
