package scenario

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// S20 — the REAL wallet page, from a node, and the node and the cloud as one product.
//
// The harness's own wallet is a Go stub (harness/wallet): it signs a CSR in-process, so nothing
// here ever drove the page a person signs on. pact-cloud's local cloud stands the real gateway
// Worker up under workerd, and its live-local runner (gateway/e2e/local-run.mjs) drives, against
// the node binary built from THIS tree:
//
//   - L1 an identity certified on the local cloud through the real routes and the real wallet page
//     (Chrome, a PRF passkey);
//   - L5 the cloud's export into the node (`import`, reviewed, then -yes), and the move signed on the
//     node's portal: /identity/{slug}/wallet → the real POST /sign → the same passkey → /wallet/return
//     → installed with the move notice; the same return again, and one with another state, refused
//     "Not installed", the certificate unchanged by both;
//   - L6 the node's export back through the cloud's real import door.
//
// A node's first leaf cannot come from the web wallet (a signing request is renew or move, and a
// node refuses the wallet for an account with no root), so a web-wallet root reaches a node by a
// move, which is what L5 is. Every case must PASS; one that never reached what it tests is
// UNREACHED and fails the scenario as such.
func TestTheRealWalletSignsANodesMove(t *testing.T) {
	ctx, _ := begin(t, registry.Spec{
		ID: "S20", Name: "the real wallet page from a node: a cloud identity imported, its move signed on the node's portal through POST /sign, replays refused, and back", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.LocalCloud, registry.Chrome},
		Timeout: 20 * time.Minute,
	})
	dir := t.TempDir()
	bin := filepath.Join(dir, "pact-gateway")
	tree, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/pact-gateway")
	build.Dir, build.Env = tree, append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the node under test: %v\n%s", err, out)
	}

	results := filepath.Join(dir, "local.json")
	run := exec.CommandContext(ctx, "node", "e2e/local-run.mjs", "--only", "L1,L5,L6", "--node-bin", bin, "--results", results)
	run.Dir = os.Getenv(registry.LocalCloudEnv)
	out, runErr := run.CombinedOutput()
	t.Logf("local-run.mjs:\n%s", trimTail(string(out), 6000))

	raw, err := os.ReadFile(results)
	if err != nil {
		t.Fatalf("the runner wrote no results (%v): it never ran", runErr)
	}
	var doc struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID, Name, Verdict string
			Evidence          []string
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Schema != "pact-results/1" {
		t.Fatalf("the results are not pact-results/1 (%v): %s", err, trim(string(raw)))
	}
	ran := map[string]bool{}
	for _, c := range doc.Cases {
		ran[c.ID] = true
		switch c.Verdict {
		case "PASS":
		case "UNREACHED":
			t.Errorf("UNREACHED %s %s: %v", c.ID, c.Name, c.Evidence)
		default:
			t.Errorf("%s %s %s: %v", c.Verdict, c.ID, c.Name, c.Evidence)
		}
	}
	for _, id := range []string{"L1", "L5", "L6"} {
		if !ran[id] {
			t.Errorf("%s did not run", id)
		}
	}
	if runErr != nil && !t.Failed() {
		t.Errorf("the runner exited %v with every case passing", runErr)
	}
}

// trimTail keeps the end of a long log, where a runner says what failed.
func trimTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

