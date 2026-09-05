package peer

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const nodeImage = "pact-gateway:harness"

// Drives a REAL containerised node over REAL mTLS and asserts the switchboard's
// answer. Until this ran, the peer driver was code that had never spoken to a node.
func TestLiveGuestTierSurfaceOverRealMTLS(t *testing.T) {
	if os.Getenv("PACT_HARNESS_LIVE") == "" {
		t.Skip("set PACT_HARNESS_LIVE=1 to run live peer tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}
	if _, err := run("image", "inspect", nodeImage); err != nil {
		t.Skipf("%s not built — run `make harness-image`", nodeImage)
	}

	const name = "pactpeer-node"
	_, _ = run("rm", "-f", name)
	// Published so the Go test process — the peer's agent — can dial it directly.
	if _, err := run("run", "-d", "--name", name, "-p", "18443:8443",
		"-e", "PACT_PUBLIC_BIND=0.0.0.0:8443",
		"-e", "PACT_PUBLIC_URL=https://127.0.0.1:18443",
		"-e", "PACT_INTERNAL_BIND=127.0.0.1:8080",
		"-e", "PACT_CLIENT_CERT=preferred",
		nodeImage, "serve"); err != nil {
		t.Fatalf("starting node: %v", err)
	}
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput() })

	// Wait for health rather than sleeping a guessed interval.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := run("exec", name, "/pact-gateway", "healthcheck"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			out, _ := run("logs", name)
			t.Fatalf("node never became healthy:\n%s", out)
		}
		time.Sleep(300 * time.Millisecond)
	}
	acct, err := run("exec", name, "/pact-gateway", "account", "create",
		"--slug", "alice", "--name", "Alice")
	if err != nil {
		t.Fatalf("creating account: %v (%s)", err, acct)
	}
	nodeFpr := ""
	for _, f := range strings.Fields(string(acct)) {
		if strings.HasPrefix(f, "sha256:") {
			nodeFpr = f
		}
	}
	if nodeFpr == "" {
		t.Fatalf("no fingerprint in account output: %s", acct)
	}
	// No restart: since P14-05a a live-created account is servable at once. The
	// workaround is gone so a regression fails here rather than hiding.

	agent, err := NewAgent("stranger")
	if err != nil {
		t.Fatal(err)
	}
	// The node's key IS pinned, because that is how a real guest arrives: they hold
	// the card (and its X-PACT-KEY) before they ever call. What is UNKNOWN here is
	// the caller — the node has never seen this agent's certificate — and that is
	// what puts them at guest tier.
	//
	// Leaving it unpinned fails, correctly: the endpoint is an IP with no SAN, so
	// the WebPKI fallback refuses. That is the pinning behaviour P13-04 documented,
	// observed from the outside.
	target := Target{Endpoint: "https://127.0.0.1:18443/a/alice/mcp", Fingerprint: nodeFpr}

	var names []string
	listDeadline := time.Now().Add(45 * time.Second)
	for {
		names, err = agent.ListTools(ctx, target)
		if err == nil {
			break
		}
		if time.Now().After(listDeadline) {
			t.Fatalf("could not list tools over mTLS: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// SPEC §5.4 / §6.2: an unknown certificate sees exactly the guest tier.
	got := strings.Join(names, ",")
	// SPEC §6.2 guest tier is redeem_invite + request_contact; §13's sealed
	// addendum adds sealed_call "at every tier", so a node advertising
	// X-PACT-SEAL offers three. An earlier version of this test asserted the 1.0
	// count of two and failed — the test was wrong, not the node.
	for _, want := range []string{"redeem_invite", "request_contact", "sealed_call"} {
		if !strings.Contains(got, want) {
			t.Errorf("guest surface is missing %q; got %v", want, names)
		}
	}
	// And nothing beyond it. send_message at guest tier would be a tier-resolution
	// failure, which is the single most security-relevant thing this driver can check.
	for _, forbidden := range []string{"send_message", "book_slot", "get_card", "update_contact"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("a STRANGER was offered %q — tier resolution is broken; got %v", forbidden, names)
		}
	}
	if len(names) != 3 {
		t.Errorf("guest tier should expose exactly redeem_invite, request_contact and "+
			"sealed_call (SPEC §6.2 + §13), got %d: %v", len(names), names)
	}
}
