package topology

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
)

// The shape tests above assert what the topology ASKS Docker for. This one stands
// real pact-gateway nodes up and asserts what is actually true of them on the wire.

func dockerRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// nodeImage is built by `make harness-image`.
const nodeImage = "pact-gateway:harness"

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("PACT_HARNESS_LIVE") == "" {
		t.Skip("set PACT_HARNESS_LIVE=1 to run live topology tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dockerRunner(ctx, "docker", "image", "inspect", nodeImage); err != nil {
		t.Skipf("%s not built — run `make harness-image`: %v", nodeImage, err)
	}
}

func TestLiveNATTopologyMakesBobUndialable(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	f := fabric.New("pacttopo", dockerRunner)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	top, err := BehindNAT(ctx, f, nodeImage)
	if err != nil {
		t.Fatalf("standing up T2: %v", err)
	}
	ready, cancelReady := context.WithTimeout(ctx, 90*time.Second)
	defer cancelReady()
	if err := top.WaitReady(ready); err != nil {
		t.Fatalf("nodes never became healthy: %v", err)
	}
	if err := top.Provision(ctx); err != nil {
		t.Fatalf("provisioning accounts: %v", err)
	}

	// Real identities, read back from real nodes.
	for _, n := range top.Nodes {
		if !strings.HasPrefix(n.Fingerprint, "sha256:") {
			t.Fatalf("%s has no usable fingerprint: %q", n.Slug, n.Fingerprint)
		}
	}
	if top.Node("alice").Fingerprint == top.Node("bob").Fingerprint {
		t.Fatal("both nodes minted the same identity")
	}

	// The asymmetry. A probe container on the WAN can open alice's public port
	// and cannot open bob's — because bob has no route in, not because we did
	// not try.
	probe := "pacttopo-probe"
	if _, err := dockerRunner(ctx, "docker", "run", "-d", "--name", probe,
		"--network", "pacttopo-wan", "alpine:3.20", "sh", "-c", "sleep 200"); err != nil {
		t.Fatalf("starting probe: %v", err)
	}
	t.Cleanup(func() { _, _ = dockerRunner(context.Background(), "docker", "rm", "-f", probe) })

	reach := func(host string) string {
		out, _ := dockerRunner(ctx, "docker", "exec", probe, "sh", "-c",
			"nc -z -w3 "+host+" 8443 >/dev/null 2>&1 && echo REACHED || echo BLOCKED")
		return strings.TrimSpace(string(out))
	}
	if got := reach(top.Node("alice").Name); got != "REACHED" {
		t.Errorf("alice is on the WAN and must be dialable, got %s", got)
	}
	if got := reach(top.Node("bob").Name); got != "BLOCKED" {
		t.Errorf("bob is behind a NAT and must NOT be dialable, got %s — the topology "+
			"does not actually isolate him, so every T2 scenario would be meaningless", got)
	}
}
