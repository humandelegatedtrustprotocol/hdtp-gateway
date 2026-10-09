package registry

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The local-cloud need is provided by a checkout holding everything its runner links into a run,
// read from the runner itself (treeLinks), and by nothing less: a gateway with public/ and no
// ceremony-dist/ passed the old probe, and S20 was promised a cloud that stopped before it started.
func TestTheLocalCloudNeedsWhatItsRunnerLinks(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is not on PATH; the probe asks the runner, which is node")
	}
	ctx := context.Background()
	repo := t.TempDir()
	gw := filepath.Join(repo, "gateway")
	if err := os.MkdirAll(filepath.Join(gw, "e2e"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := func(body string) {
		if err := os.WriteFile(filepath.Join(gw, "e2e", "local-run.mjs"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(repo, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(LocalCloudEnv, gw)
	t.Setenv("WORKOS_TEST_CLIENT_ID", "client")
	t.Setenv("WORKOS_TEST_API_KEY", "key")
	runner(`export const treeLinks = () => ['gateway/node_modules', 'gateway/ceremony-dist', 'gateway/public']
// The real runner's guard: it starts a run when argv[1] is itself.
if (process.argv[1]?.endsWith('local-run.mjs')) { console.log('gateway/main-ran'); process.exit(1) }`)
	mk("gateway/node_modules")
	mk("gateway/public")
	err := probe(ctx, LocalCloud)
	if err == nil || !strings.Contains(err.Error(), "ceremony-dist") {
		t.Errorf("a checkout with public/ and no ceremony-dist/ provided the local cloud: %v", err)
	}
	mk("gateway/ceremony-dist")
	if err := probe(ctx, LocalCloud); err != nil {
		t.Errorf("a checkout with everything its runner links was refused: %v", err)
	}
	runner(`export const STEPS = []`)
	if err := probe(ctx, LocalCloud); err == nil || !strings.Contains(err.Error(), "treeLinks") {
		t.Errorf("a runner that cannot say what it links provided the need: %v", err)
	}
	t.Setenv(LocalCloudEnv, "")
	if err := probe(ctx, LocalCloud); err == nil {
		t.Error("an unset variable provided the local cloud")
	}
}
