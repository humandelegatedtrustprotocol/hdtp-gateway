package fabric

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests in fabric_test.go assert what Docker was ASKED to do. This one asserts
// what Docker actually DID — because the property the topologies rest on ("a node on
// an internal network genuinely cannot be reached") is a claim about Docker's
// behaviour, not about our argv.
//
// This project spent four review passes on fixes that were correct where they were
// written and absent where they were reached. A fabric driver verified only by a
// recorder would be the same shape of mistake.

func dockerRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("PACT_HARNESS_LIVE") == "" {
		t.Skip("set PACT_HARNESS_LIVE=1 to run live Docker tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dockerRunner(ctx, "docker", "version", "--format", "{{.Server.Os}}"); err != nil {
		t.Skipf("no Docker daemon: %v", err)
	}
}

func TestLiveInternalNetworkIsGenuinelyUnreachable(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	f := New("pactlive1", dockerRunner)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	inside, err := f.Network(ctx, "lan", NetOpts{Internal: true})
	if err != nil {
		t.Fatalf("creating internal network: %v", err)
	}

	// A container with only an internal network must not reach the outside.
	// 169.254.169.254 is deliberate: it is the link-local address the media
	// SSRF guard refuses, so a route to it is exactly what must not exist.
	_, err = f.Container(ctx, Spec{
		Name: "isolated", Image: natImage, Network: inside,
		Cmd: []string{"sh", "-c", "sleep 120"},
	})
	if err != nil {
		t.Fatalf("starting isolated container: %v", err)
	}

	out, _ := dockerRunner(ctx, "docker", "exec", "pactlive1-isolated",
		"sh", "-c", "ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
	if !strings.Contains(string(out), "BLOCKED") {
		t.Fatalf("a container on an --internal network reached the internet, so T2/T3 "+
			"isolation is not real: %q", out)
	}
}

func TestLiveNATGivesOutboundButNoInbound(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	f := New("pactlive2", dockerRunner)
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
		Name: "peer", Image: natImage, Network: wan,
		Cmd: []string{"sh", "-c", "while true; do echo -e 'HTTP/1.1 200 OK\\r\\n\\r\\nPONG' | nc -l -p 8080; done"},
	}); err != nil {
		t.Fatal(err)
	}
	// A node behind the NAT.
	if _, err := f.Container(ctx, Spec{
		Name: "node", Image: natImage, Network: lan,
		Cmd: []string{"sh", "-c", "sleep 240"},
	}); err != nil {
		t.Fatal(err)
	}

	// The asymmetry that defines a NAT: the peer cannot open a connection inward.
	out, _ := dockerRunner(ctx, "docker", "exec", "pactlive2-peer",
		"sh", "-c", "nc -z -w2 pactlive2-node 22 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
	if !strings.Contains(string(out), "BLOCKED") {
		t.Errorf("the WAN peer dialled INTO the NATed node; the topology is not a NAT: %q", out)
	}

	// And artifacts must come back even from a live run.
	dir := t.TempDir()
	_ = f.Collect(ctx, dir)
	if _, err := os.Stat(filepath.Join(dir, "pactlive2-peer.log")); err != nil {
		t.Errorf("no logs collected from a live container: %v", err)
	}
}
