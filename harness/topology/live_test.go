package topology

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
)

// The shape tests above assert what the topology ASKS Docker for. This one stands
// real hdtp-gateway nodes up and asserts what is actually true of them on the wire.

func TestLiveNATTopologyMakesBobUndialable(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "F3", Name: "T2: a node behind the NAT cannot be dialled, one on the WAN can", Tier: registry.Fabric,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage},
		Timeout: 6 * time.Minute,
	})

	f := fabric.New(fabric.PrefixFor(registry.SpecOf(ctx).ID), fabric.Local)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	top, err := BehindNAT(ctx, f, images.Node)
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
	probe := f.Name("probe")
	if _, err := fabric.Local(ctx, "docker", "run", "-d", "--name", probe,
		"--network", f.Name("wan"), images.Alpine, "sh", "-c", "sleep 200"); err != nil {
		t.Fatalf("starting probe: %v", err)
	}
	t.Cleanup(func() { _, _ = fabric.Local(context.Background(), "docker", "rm", "-f", probe) })

	reach := func(host string) string {
		out, _ := fabric.Local(ctx, "docker", "exec", probe, "sh", "-c",
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
