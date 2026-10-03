package invariant

import (
	"context"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/topology"
)

// Proves the audit-chain invariant against real nodes: it stops each one and
// verifies its hash chain in a sidecar. Until this ran, "the invariant passes" was
// a claim about code that had never touched a real chain.
func TestLiveAuditChainInvariantVerifiesRealNodes(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "F4", Name: "the audit-chain invariant verifies the chains of real nodes (T1)", Tier: registry.Fabric,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage},
		Timeout: 5 * time.Minute,
	})

	f := fabric.New(fabric.PrefixFor(registry.SpecOf(ctx).ID), fabric.Local)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	top, err := topology.LAN(ctx, f, images.Node)
	if err != nil {
		t.Fatal(err)
	}
	ready, cancelReady := context.WithTimeout(ctx, 90*time.Second)
	defer cancelReady()
	if err := top.WaitReady(ready); err != nil {
		t.Fatal(err)
	}
	if err := top.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	rep := All(ctx, f, top)
	t.Logf("invariant report:\n%s", rep)
	if !rep.OK() {
		t.Fatalf("invariants failed on a clean run: %s", rep)
	}
	// The one that must genuinely have looked at a chain.
	var audit *Result
	for i := range rep {
		if rep[i].Name == "audit-chain" {
			audit = &rep[i]
		}
	}
	if audit == nil || audit.Status != Pass {
		t.Fatalf("the audit-chain invariant did not verify real nodes: %+v", audit)
	}
}
