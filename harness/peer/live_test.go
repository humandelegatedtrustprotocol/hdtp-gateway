package peer

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/registry"
	"github.com/tech-sumit/pact-gateway/harness/wallet"
)

// Drives a REAL containerised node over REAL mTLS and asserts the switchboard's
// answer. Until this ran, the peer driver was code that had never spoken to a node.
func TestLiveGuestTierSurfaceOverRealMTLS(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "F5", Name: "a stranger sees exactly the guest tier, over real mTLS", Tier: registry.Fabric,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage},
		Timeout: 4 * time.Minute,
	})
	run := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}

	const name = "pactpeer-node"
	_, _ = run("rm", "-f", name)
	// Published so the Go test process — the peer's agent — can dial it directly.
	if _, err := run("run", "-d", "--name", name, "-p", "18443:8443",
		"-e", "PACT_PUBLIC_BIND=0.0.0.0:8443",
		// A NAME, because a wallet does not issue a leaf for a loopback address (PACT §14.2 rule
		// 5). The agent dials it to the published port below, which is DNS's job for a real caller.
		"-e", "PACT_PUBLIC_URL=https://alice.harness.example:18443",
		"-e", "PACT_INTERNAL_BIND=127.0.0.1:8080",
		"-e", "PACT_CLIENT_CERT=preferred",
		images.Node, "serve"); err != nil {
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
	if acct, err := run("exec", name, "/pact-gateway", "account", "create",
		"--slug", "alice", "--name", "Alice"); err != nil {
		t.Fatalf("creating account: %v (%s)", err, acct)
	}
	// An account is nobody until a wallet has signed it a leaf (PACT §2): this one's owner is
	// played by the harness. Until that happens the node has no certificate to present, and
	// every dial ends `tls: internal error` — which is what this test did from the day 1.x
	// went until 2026-09-19, skipped, because PACT_HARNESS_LIVE is not set by any hook.
	alice, err := wallet.New("Alice")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := alice.Certify(ctx, wallet.Docker(name), "alice", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// No restart: a live-created account is servable as soon as it is certified. There is no
	// workaround here so a regression fails rather than hiding.

	agent, err := NewAgent("stranger")
	if err != nil {
		t.Fatal(err)
	}
	// The node IS pinned, because that is how a real guest arrives: they hold its card — its
	// leaf, and through the invite landing its root — before they ever call. What is UNKNOWN
	// here is the caller: the node has never seen this agent's chain, and that is what puts them
	// at guest tier.
	//
	// Leaving it unpinned fails, correctly: what the node presents is its own chain, which no
	// public authority signed, so the WebPKI fallback refuses.
	target := Target{Endpoint: pin.Endpoint, Dial: "127.0.0.1:18443", Root: pin.Root, Leaf: pin.Leaf}
	if pin.Endpoint != "https://alice.harness.example:18443/a/alice/mcp" {
		t.Fatalf("the leaf names %q, not the address this node was given", pin.Endpoint)
	}

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
