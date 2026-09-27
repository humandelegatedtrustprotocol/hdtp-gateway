package fabric

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// The tests in fabric_test.go assert what Docker was ASKED to do. This one asserts
// what Docker actually DID — because the property the topologies rest on ("a node on
// an internal network genuinely cannot be reached") is a claim about Docker's
// behaviour, not about our argv.
//
// This project spent four review passes on fixes that were correct where they were
// written and absent where they were reached. A fabric driver verified only by a
// recorder would be the same shape of mistake.

func TestLiveInternalNetworkIsGenuinelyUnreachable(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "F1", Name: "a container on an internal network cannot reach the outside", Tier: registry.Fabric,
		Needs:   []registry.Need{registry.Docker},
		Timeout: 4 * time.Minute,
	})

	f := New(PrefixFor(registry.SpecOf(ctx).ID), Local)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	inside, err := f.Network(ctx, "lan", NetOpts{Internal: true})
	if err != nil {
		t.Fatalf("creating internal network: %v", err)
	}

	// A container with only an internal network must not reach the outside: it pings a public
	// address (1.1.1.1), which answers from anywhere that has a route off the segment.
	_, err = f.Container(ctx, Spec{
		Name: "isolated", Image: images.Alpine, Network: inside,
		Cmd: []string{"sh", "-c", "sleep 120"},
	})
	if err != nil {
		t.Fatalf("starting isolated container: %v", err)
	}

	out, _ := Local(ctx, "docker", "exec", f.Name("isolated"),
		"sh", "-c", "ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
	if !strings.Contains(string(out), "BLOCKED") {
		t.Fatalf("a container on an --internal network reached the internet, so T2 "+
			"isolation is not real: %q", out)
	}
}

func TestLiveNATGivesOutboundButNoInbound(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "F2", Name: "the NAT router admits no inbound connection, and a live run collects logs", Tier: registry.Fabric,
		Needs:   []registry.Need{registry.Docker},
		Timeout: 5 * time.Minute,
	})

	f := New(PrefixFor(registry.SpecOf(ctx).ID), Local)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	wan, err := f.Network(ctx, "wan", NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	lan, err := f.Network(ctx, "lan", NetOpts{Internal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.NAT(ctx, "router", wan, lan); err != nil {
		t.Fatalf("starting NAT router: %v", err)
	}

	// A peer on the WAN, serving something dialable.
	if _, err := f.Container(ctx, Spec{
		Name: "peer", Image: images.Alpine, Network: wan,
		Cmd: []string{"sh", "-c", "while true; do echo -e 'HTTP/1.1 200 OK\\r\\n\\r\\nPONG' | nc -l -p 8080; done"},
	}); err != nil {
		t.Fatal(err)
	}
	// A node behind the NAT.
	if _, err := f.Container(ctx, Spec{
		Name: "node", Image: images.Alpine, Network: lan,
		Cmd: []string{"sh", "-c", "sleep 240"},
	}); err != nil {
		t.Fatal(err)
	}

	// The asymmetry that defines a NAT: the peer cannot open a connection inward.
	out, _ := Local(ctx, "docker", "exec", f.Name("peer"),
		"sh", "-c", "nc -z -w2 "+f.Name("node")+" 22 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
	if !strings.Contains(string(out), "BLOCKED") {
		t.Errorf("the WAN peer dialled INTO the NATed node; the topology is not a NAT: %q", out)
	}

	// And artifacts must come back even from a live run.
	dir := t.TempDir()
	_ = f.Collect(ctx, dir)
	if _, err := os.Stat(filepath.Join(dir, f.Name("peer")+".log")); err != nil {
		t.Errorf("no logs collected from a live container: %v", err)
	}
}
