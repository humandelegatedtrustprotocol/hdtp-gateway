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
)

// Kind names a topology from the design document.
type Kind string

const (
	T1LAN       Kind = "T1-lan"
	T2NAT       Kind = "T2-nat"
	T3DoubleNAT Kind = "T3-double-nat"
)

// PublicPort is the port every node's public surface binds inside its container.
const PublicPort = 8443

// Node is one running pact-gateway.
type Node struct {
	Name      string
	Slug      string
	Container *fabric.Container
	PublicURL string
	// Fingerprint is the account's SPKI fingerprint (PACT §2), read back from the
	// node after its account is created. Empty until Provision runs.
	Fingerprint string
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

// nodeSpec builds the container spec for one node. Every knob is an environment
// variable because SPEC §12.2 makes env the highest-precedence config layer, so a
// topology needs no config files inside the image.
func nodeSpec(name, image string, net *fabric.Network, prefix string, extra map[string]string) fabric.Spec {
	env := map[string]string{
		"PACT_PUBLIC_BIND": fmt.Sprintf("0.0.0.0:%d", PublicPort),
		"PACT_PUBLIC_URL":  fmt.Sprintf("https://%s-%s:%d", prefix, name, PublicPort),
		// The portal stays on loopback inside the container: SPEC §8.3 refuses a
		// non-loopback internal bind without auth and TLS, and the harness has no
		// business weakening that to make itself easier to drive.
		"PACT_INTERNAL_BIND": "127.0.0.1:8080",
	}
	for k, v := range extra {
		env[k] = v
	}
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
		c, err := f.Container(ctx, nodeSpec(slug, image, net, f.Prefix(), nil))
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
		c, err := f.Container(ctx, nodeSpec(spec.slug, image, spec.net, f.Prefix(), nil))
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

// DoubleNAT is T3: neither node is dialable, so a relay is the only path that can
// carry a message between them (SPEC §10.1). The relay itself sits on the WAN.
func DoubleNAT(ctx context.Context, f *fabric.Fabric, image string) (*Topo, error) {
	wan, err := f.Network(ctx, "wan", fabric.NetOpts{})
	if err != nil {
		return nil, err
	}
	t := &Topo{Kind: T3DoubleNAT, Fab: f, Image: image}

	// The relay is reachable by both sides; that is the whole point of a relay.
	relay, err := f.Container(ctx, nodeSpec("relay", image, wan, f.Prefix(), map[string]string{
		"PACT_RELAY": "true",
		// A relay verifies signatures with the caller's client certificate, so it
		// must run on a listener that requests one (SPEC §10.5).
		"PACT_CLIENT_CERT": "preferred",
		"PACT_SEAL":        "optional",
	}))
	if err != nil {
		return nil, err
	}
	t.Nodes = append(t.Nodes, &Node{
		Name: relay.Name, Slug: "relay", Container: relay, Reachable: true,
		PublicURL: fmt.Sprintf("https://%s:%d", relay.Name, PublicPort),
	})

	for _, slug := range []string{"alice", "bob"} {
		lan, err := f.Network(ctx, "lan-"+slug, fabric.NetOpts{Internal: true})
		if err != nil {
			return nil, err
		}
		if _, err := f.NAT(ctx, "nat-"+slug, wan, lan); err != nil {
			return nil, err
		}
		c, err := f.Container(ctx, nodeSpec(slug, image, lan, f.Prefix(), map[string]string{
			// Relay-assisted mode forces seal=required (SPEC §10.1); the config
			// validator refuses the pair otherwise, so both are set together.
			"PACT_MODE":        "relay-assisted",
			"PACT_SEAL":        "required",
			"PACT_GATEWAY_URL": fmt.Sprintf("https://%s:%d", relay.Name, PublicPort),
		}))
		if err != nil {
			return nil, err
		}
		t.Nodes = append(t.Nodes, &Node{
			Name: c.Name, Slug: slug, Container: c, Reachable: false,
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
		if err := waitOne(ctx, t.Fab, n); err != nil {
			return err
		}
	}
	return nil
}

func waitOne(ctx context.Context, f *fabric.Fabric, n *Node) error {
	var last error
	for {
		if _, err := f.Exec(ctx, n.Container, "/pact-gateway", "healthcheck"); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("topology: %s never became healthy: %w (last: %v)", n.Name, ctx.Err(), last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Provision creates one account per node and records its fingerprint, which is the
// identity every later scenario pins against (PACT §2).
func (t *Topo) Provision(ctx context.Context) error {
	for _, n := range t.Nodes {
		out, err := t.Fab.Exec(ctx, n.Container,
			"/pact-gateway", "account", "create", "--slug", n.Slug, "--name", strings.ToUpper(n.Slug[:1])+n.Slug[1:])
		if err != nil {
			return fmt.Errorf("topology: creating account on %s: %w", n.Name, err)
		}
		fpr := parseFingerprint(string(out))
		if fpr == "" {
			return fmt.Errorf("topology: %s created an account with no fingerprint in %q", n.Name, out)
		}
		n.Fingerprint = fpr
	}
	// No restart here on purpose. The node used to load account certificates at
	// startup only, so an account created on a running node was unreachable until
	// it restarted, and this function worked around that. P14-05a fixed the node;
	// the workaround is gone so that a regression fails a scenario instead of
	// being quietly absorbed.
	return nil
}

// parseFingerprint reads the fingerprint out of `account create` output, which
// reads: created <slug>  fingerprint sha256:<base64url>
func parseFingerprint(out string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "sha256:") {
			return f
		}
	}
	return ""
}
