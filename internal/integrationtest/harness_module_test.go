package integrationtest

// The scenario harness (docs/harness-design.md) drives a real browser over CDP and
// orchestrates containers and VMs. That means dependencies — chromedp and its tree —
// that must never reach the shipped artifact.
//
// A build tag would keep them out of the BINARY but not out of go.mod, go.sum, or
// govulncheck's surface. A separate module keeps them out of all four. These tests
// are what stop that boundary from quietly eroding: Go excludes nested modules from
// the parent's ./... automatically, so the isolation is real, but only for as long
// as harness/ actually has its own go.mod.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// harnessOnlyDeps are module paths that belong to the harness and must never appear
// in the root module. chromedp is the one the separation exists for; the others are
// the usual ways a test harness leaks into a product.
var harnessOnlyDeps = []string{
	"github.com/chromedp/",
	"github.com/testcontainers/",
	"github.com/docker/docker",
}

func TestHarnessIsASeparateModule(t *testing.T) {
	root := repoRoot(t)
	gomod := filepath.Join(root, "harness", "go.mod")
	b, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatalf("harness/go.mod is missing, so the harness would share the root module "+
			"and its dependencies would land in the shipped artifact: %v", err)
	}
	want := "module github.com/tech-sumit/pact-gateway/harness"
	if !strings.Contains(string(b), want) {
		t.Errorf("harness/go.mod does not declare %q", want)
	}
}

func TestRootModuleCarriesNoHarnessDependency(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, dep := range harnessOnlyDeps {
			if strings.Contains(string(b), dep) {
				t.Errorf("%s references %q — a harness dependency reached the root module, "+
					"which puts it in the shipped artifact's dependency and vulnerability surface", f, dep)
			}
		}
	}
}

func TestRootPackageListExcludesTheHarness(t *testing.T) {
	root := repoRoot(t)
	// Dir MUST be the repo root. `go test` runs each test in its own PACKAGE
	// directory, so an unanchored `go list ./...` here would enumerate only
	// internal/integrationtest/... — which can never contain the harness, so the
	// check would pass no matter what. Verified by removing harness/go.mod and
	// watching this fail.
	cmd := exec.Command("go", "list", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(line, "/harness") {
			t.Errorf("`go list ./...` in the root module returned %q — the harness is being "+
				"compiled as part of the product, so `make check` and the build now carry its "+
				"dependencies", line)
		}
	}
}

// The image must not carry the harness either — it is orchestration, not product.
func TestShippedImageDoesNotCopyTheHarness(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{"Dockerfile", "Dockerfile.full"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue // a variant that does not exist cannot leak anything
		}
		for _, line := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToUpper(l), "COPY") {
				continue
			}
			if strings.Contains(l, "harness") {
				t.Errorf("%s copies the harness into the image: %q", f, l)
			}
		}
	}
}
