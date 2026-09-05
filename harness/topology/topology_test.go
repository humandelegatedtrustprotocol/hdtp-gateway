package topology

import (
	"context"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
)

type rec struct{ calls []string }

func (r *rec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	return []byte("created x  fingerprint sha256:AAAA"), nil
}
func (r *rec) saw(sub string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestLANPutsBothNodesOnOneReachableSegment(t *testing.T) {
	r := &rec{}
	f := fabric.New("tp", r.run)
	top, err := LAN(context.Background(), f, "img")
	if err != nil {
		t.Fatal(err)
	}
	if len(top.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(top.Nodes))
	}
	for _, n := range top.Nodes {
		if !n.Reachable {
			t.Errorf("%s is marked unreachable on the LAN topology", n.Slug)
		}
	}
	if r.saw("--internal") {
		t.Error("T1 created an internal network; the control topology must be fully reachable")
	}
}

// The property T2 exists for: bob must be on a network with no route in.
func TestNATLeavesOnlyAliceReachable(t *testing.T) {
	r := &rec{}
	f := fabric.New("tp", r.run)
	top, err := BehindNAT(context.Background(), f, "img")
	if err != nil {
		t.Fatal(err)
	}
	if a := top.Node("alice"); a == nil || !a.Reachable {
		t.Error("alice should be reachable on the WAN side")
	}
	if b := top.Node("bob"); b == nil || b.Reachable {
		t.Error("bob is behind a NAT and must not be marked reachable")
	}
	if !r.saw("network create --internal tp-lan") {
		t.Errorf("bob's segment is not internal, so he is dialable: %v", r.calls)
	}
	if !r.saw("MASQUERADE") {
		t.Error("no NAT router was installed")
	}
}

// T3's whole point: neither peer can be dialled, so only the relay can carry a
// message. The nodes must therefore be configured relay-assisted, and SPEC §10.1
// forces seal=required with it — the config validator refuses the pair otherwise,
// so getting this wrong means the nodes refuse to start.
func TestDoubleNATMakesTheRelayTheOnlyPath(t *testing.T) {
	r := &rec{}
	f := fabric.New("tp", r.run)
	top, err := DoubleNAT(context.Background(), f, "img")
	if err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"alice", "bob"} {
		n := top.Node(slug)
		if n == nil {
			t.Fatalf("%s missing", slug)
		}
		if n.Reachable {
			t.Errorf("%s is behind a NAT and must not be marked reachable", slug)
		}
	}
	if rl := top.Node("relay"); rl == nil || !rl.Reachable {
		t.Fatal("the relay must be reachable by both sides")
	}
	if !r.saw("PACT_MODE=relay-assisted") {
		t.Errorf("nodes are not in relay-assisted mode: %v", r.calls)
	}
	if !r.saw("PACT_SEAL=required") {
		t.Error("relay-assisted mode forces seal=required (SPEC §10.1); the node will refuse to start without it")
	}
	if !r.saw("PACT_RELAY=true") {
		t.Error("the relay node was not started in relay mode")
	}
	// A relay verifies signatures with the caller's client certificate, so it must
	// request one. On an edge-terminated listener it never would (SPEC §10.5).
	if !r.saw("PACT_CLIENT_CERT=preferred") {
		t.Error("the relay does not request client certificates, so it cannot verify senders")
	}
	// Two separate internal segments, not one shared one — otherwise the peers
	// could reach each other directly and the topology proves nothing.
	if !r.saw("network create --internal tp-lan-alice") || !r.saw("network create --internal tp-lan-bob") {
		t.Errorf("peers share a segment, so they are not actually isolated: %v", r.calls)
	}
}

func TestProvisionRecordsFingerprints(t *testing.T) {
	r := &rec{}
	f := fabric.New("tp", r.run)
	top, _ := LAN(context.Background(), f, "img")
	if err := top.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range top.Nodes {
		if n.Fingerprint != "sha256:AAAA" {
			t.Errorf("%s has fingerprint %q; scenarios pin identity on this", n.Slug, n.Fingerprint)
		}
	}
}

func TestParseFingerprintIgnoresProseAroundIt(t *testing.T) {
	if got := parseFingerprint("created alice  fingerprint sha256:aB6w_x\n"); got != "sha256:aB6w_x" {
		t.Errorf("got %q", got)
	}
	if got := parseFingerprint("created alice with no fingerprint"); got != "" {
		t.Errorf("invented a fingerprint from output that had none: %q", got)
	}
}
