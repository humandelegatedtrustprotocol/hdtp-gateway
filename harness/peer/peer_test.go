package peer

import (
	"strings"
	"testing"
)

func TestEachAgentGetsItsOwnIdentity(t *testing.T) {
	a, err := NewAgent("alice-agent")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAgent("bob-agent")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.Fingerprint(), "sha256:") {
		t.Errorf("fingerprint is not a HDTP §2 identity: %q", a.Fingerprint())
	}
	// Identity IS the caller in HDTP. Two simulated contacts sharing one would
	// make every tier and permission assertion in every scenario meaningless.
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two agents minted the same identity")
	}
}

// A peer trusts a node by PINNED KEY, not by WebPKI (SPEC §2). An empty root pool
// is what makes a mis-pinned peer fail closed rather than fall back to the system
// trust store.
func TestAgentTrustsByPinNotWebPKI(t *testing.T) {
	a, err := NewAgent("x")
	if err != nil {
		t.Fatal(err)
	}
	if a.Client.Roots == nil {
		t.Fatal("Roots is nil, so crypto/tls would use the SYSTEM pool — a peer with any " +
			"publicly-trusted certificate would be accepted as the node")
	}
	if len(a.Client.Roots.Subjects()) != 0 { //nolint:staticcheck // empty-pool assertion
		t.Error("the root pool is not empty; pinning is not the only trust path")
	}
}

// A refusal is an ANSWER, not a transport failure. A driver that swallowed the
// error flag would make "the node refused you" look like a successful call, and
// every negative-path scenario would silently pass.
func TestRefusalsSurfaceAsErrors(t *testing.T) {
	res := map[string]any{
		"isError": true,
		"content": []map[string]any{{"type": "text", "text": `{"code":"permission_denied"}`}},
	}
	text, err := renderResult(res)
	if err == nil {
		t.Fatal("a refusal was reported as success")
	}
	if !strings.Contains(text, "permission_denied") {
		t.Errorf("the refusal code was lost: %q", text)
	}
}

func TestSuccessfulResultsReturnTheirText(t *testing.T) {
	res := map[string]any{
		"content": []map[string]any{{"type": "text", "text": "delivered"}},
	}
	text, err := renderResult(res)
	if err != nil {
		t.Fatalf("a successful result was reported as an error: %v", err)
	}
	if text != "delivered" {
		t.Errorf("got %q", text)
	}
}
