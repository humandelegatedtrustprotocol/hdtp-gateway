package invariant

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/topology"
)

const nodeImage = "pact-gateway:harness"

func dockerRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Proves the audit-chain invariant against real nodes: it stops each one and
// verifies its hash chain in a sidecar. Until this ran, "the invariant passes" was
// a claim about code that had never touched a real chain.
func TestLiveAuditChainInvariantVerifiesRealNodes(t *testing.T) {
	if os.Getenv("PACT_HARNESS_LIVE") == "" {
		t.Skip("set PACT_HARNESS_LIVE=1 to run live invariant tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := dockerRunner(ctx, "docker", "image", "inspect", nodeImage); err != nil {
		t.Skipf("%s not built — run `make harness-image`", nodeImage)
	}

	f := fabric.New("pactinv", dockerRunner)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = f.Teardown(c)
	})

	top, err := topology.LAN(ctx, f, nodeImage)
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
