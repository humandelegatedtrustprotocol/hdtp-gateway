package scenario

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"

	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// S19 — the cloud's Go conformance battery, aimed at a node.
//
// pact-cloud/gateway/conformance is the one battery of the wire both hosts are held to: the guest
// tier, chain_required, the per-root guest budget with a second root that must get through, every
// envelope negative with its paired control, invite no-oracle 404s and single use, sealed answers
// read by the reference client, and the audit rows hashed and linked as the reference hashes them.
// It ran only against the cloud. Its target is now a parameter (its target_test.go): the endpoint,
// the card, where to dial, and the owner's door — for a node, `/owner/mcp` with an owner token.
// The subtests that cannot apply to a node are in its divergence list, which it holds itself.
//
// The battery is built against THIS tree (a go.work that replaces the node module, as `make
// dependents` does), so it is this node's code under test from both ends of the wire.
//
// Alice's first leaf is short-lived and renewed at once, and the battery starts after it expires,
// so the stale-kid case has a former kid to send (PACT §14.4); the battery skips that case without
// one, and here nothing may skip.
func TestTheConformanceBatteryPassesAgainstANode(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S19", Name: "the cloud's Go conformance battery against a node, through the node's own owner door", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome, registry.CloudBattery},
		Timeout: 20 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The first leaf lives a few minutes; the renewal after it a year. Once the first is past its
	// notAfter its key is one this endpoint held and holds no longer, which is what the battery's
	// stale-kid case needs (PACT §14.4): a renewal alone leaves the superseded key held until then.
	shortUntil := time.Now().Add(4 * time.Minute).Truncate(time.Second)
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net, PublishPublic: true, LeafUntil: shortUntil})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	former := pactidentity.Fingerprint(leafSPKI(t, alice.Pin.Leaf))
	if alice.Pin, err = alice.Wallet.Certify(ctx, topology.NodeOf(w.Fab, alice.Node), "alice", "renew", ""); err != nil {
		t.Fatalf("renewing alice's leaf: %v", err)
	}
	// An absence cannot be polled for: wait out the first leaf, with a margin (docs/testing.md).
	select {
	case <-time.After(time.Until(shortUntil) + 15*time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	token, err := OwnerToken(ctx, w.Fab, alice.Node, "conformance")
	if err != nil {
		t.Fatal(err)
	}
	cardFile := filepath.Join(t.TempDir(), "alice.vcf")
	if err := os.WriteFile(cardFile, []byte(exportCard(ctx, t, alice)), 0o600); err != nil {
		t.Fatal(err)
	}

	events, code := battery(ctx, t, map[string]string{
		"PACT_LIVE_TARGET":     "node",
		"PACT_LIVE_ENDPOINT":   alice.Pin.Endpoint,
		"PACT_LIVE_CARD":       cardFile,
		"PACT_LIVE_DIAL":       "127.0.0.1:" + alice.PublicPort,
		"PACT_LIVE_OWNER_URL":  "http://127.0.0.1:" + alice.OwnerPort + "/owner/mcp",
		"PACT_LIVE_TOKEN":      token,
		"PACT_LIVE_FORMER_KID": former,
	})
	v := judge(events)
	t.Logf("battery against the node: %d passed, %d failed, %d skipped (exit %d)", len(v.passed), len(v.failed), len(v.skipped), code)
	for _, name := range v.failed {
		t.Logf("FAIL %s\n%s", name, v.output[name])
	}
	for _, name := range v.skipped {
		t.Logf("SKIP %s\n%s", name, v.output[name])
	}
	switch {
	case len(v.unreached) > 0:
		t.Fatalf("UNREACHED: the battery never reached the layer it tests in %v", v.unreached)
	case len(v.failed) > 0:
		t.Fatalf("the node failed %d of the battery's cases: %v", len(v.failed), v.failed)
	case len(v.skipped) > 0:
		t.Fatalf("the battery skipped %v against a node that has every input it asks for: a skip is not a pass", v.skipped)
	case code != 0:
		t.Fatalf("the battery exited %d with no case failing", code)
	}
	// Both live tests ran, not just the offline ones: the battery skips whole tests without a target.
	for _, top := range []string{"TestLiveConformance", "TestCertificateConformance"} {
		if !v.passedSet[top] {
			t.Errorf("%s did not pass as a whole", top)
		}
	}
}

// leafSPKI is a leaf certificate's key.
func leafSPKI(t *testing.T, der []byte) []byte {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the pin's leaf: %v", err)
	}
	return c.RawSubjectPublicKeyInfo
}

// testEvent is one line of `go test -json`.
type testEvent struct {
	Action, Test, Output string
}

// battery runs the conformance battery with env added, built against this tree, and returns its
// `go test -json` events and exit status.
func battery(ctx context.Context, t *testing.T, env map[string]string) ([]testEvent, int) {
	t.Helper()
	dir := os.Getenv(registry.CloudBatteryEnv)
	tree, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	goCmd := func(dir string, args ...string) {
		t.Helper()
		c := exec.CommandContext(ctx, "go", args...)
		c.Dir, c.Env = dir, append(os.Environ(), "GOWORK=")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, out)
		}
	}
	// A replace, not a use: the battery pins the node by a version, and this tree's commit need
	// not exist anywhere but here (the Makefile's `dependents` says why).
	goCmd(ws, "work", "init", dir)
	goCmd(ws, "work", "edit", "-replace=github.com/pact-cloud/pact-gateway="+tree)

	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-timeout", "15m", "./")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK="+filepath.Join(ws, "go.work"),
		"GOPRIVATE=github.com/pact-cloud/*", "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url.git@github.com:.insteadOf", "GIT_CONFIG_VALUE_0=https://github.com/")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running the battery: %v", err)
		}
		code = ee.ExitCode()
	}
	var events []testEvent
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e testEvent
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			events = append(events, e)
		}
	}
	if len(events) == 0 {
		t.Fatalf("the battery printed no test events (exit %d): %s", code, trim(stderr.String()+string(out)))
	}
	return events, code
}

// verdicts is what the battery's events say, per test.
type verdicts struct {
	passed, failed, skipped, unreached []string
	passedSet                          map[string]bool
	output                             map[string]string
}

// judge reads the events. A failed test whose own output starts a line with UNREACHED never
// reached the layer it tests; a parent that failed only because a child did is not counted twice.
func judge(events []testEvent) verdicts {
	v := verdicts{passedSet: map[string]bool{}, output: map[string]string{}}
	for _, e := range events {
		if e.Test != "" && e.Action == "output" {
			v.output[e.Test] += e.Output
		}
	}
	failed := map[string]bool{}
	for _, e := range events {
		switch e.Action {
		case "pass":
			if e.Test != "" {
				v.passed = append(v.passed, e.Test)
				v.passedSet[e.Test] = true
			}
		case "skip":
			if e.Test != "" {
				v.skipped = append(v.skipped, e.Test)
			}
		case "fail":
			if e.Test != "" {
				failed[e.Test] = true
			}
		}
	}
	for name := range failed {
		leaf := true
		for other := range failed {
			if strings.HasPrefix(other, name+"/") {
				leaf = false
			}
		}
		if !leaf {
			continue
		}
		v.failed = append(v.failed, name)
		if strings.Contains(v.output[name], "UNREACHED:") {
			v.unreached = append(v.unreached, name)
		}
	}
	sort.Strings(v.failed)
	sort.Strings(v.unreached)
	return v
}
