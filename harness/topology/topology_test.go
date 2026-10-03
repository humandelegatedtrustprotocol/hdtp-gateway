package topology

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
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

// A node's identity is its owner's ROOT, and Provision is where a node gets one: the wallet
// answers the node's certificate request, and the chain goes back in. This runs the whole
// ceremony against a recording runner that plays the node's CLI — a real request for a real key,
// so the wallet really issues — and holds Provision to what a scenario then relies on.
func TestProvisionCertifiesEachAccountUnderItsOwnersRoot(t *testing.T) {
	r := &rec{}
	var installed []string
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		switch {
		case strings.Contains(line, "account csr"):
			host, err := hdtpidentity.GenerateKey("p256")
			if err != nil {
				t.Fatal(err)
			}
			slug := args[len(args)-1]
			der, err := hdtpidentity.CSRNew(slug, host, "https://tp-"+slug+":8443/a/"+slug+"/mcp", "")
			if err != nil {
				t.Fatal(err)
			}
			return append([]byte("signup request for the wallet\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})...), nil
		case strings.Contains(line, "account install-leaf"):
			installed = append(installed, line)
		}
		return r.run(ctx, name, args...)
	}
	f := fabric.New("tp", run)
	top, _ := LAN(context.Background(), f, "img")
	if err := top.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, n := range top.Nodes {
		if n.Wallet == nil || n.Fingerprint != n.Wallet.Fingerprint || n.Pin.Root != n.Fingerprint {
			t.Fatalf("%s is not pinned by its owner's root: %q", n.Slug, n.Fingerprint)
		}
		if seen[n.Fingerprint] {
			t.Errorf("two people share the root %s", n.Fingerprint)
		}
		seen[n.Fingerprint] = true
		vr := hdtpidentity.ValidateChain([][]byte{n.Pin.Leaf, n.Wallet.RootDER},
			hdtpidentity.ChainOpts{Now: time.Now(), ExpectedRoot: n.Fingerprint, ExpectedEndpoint: n.Pin.Endpoint})
		if !vr.OK {
			t.Errorf("%s's chain does not validate to its root at %s: rule %d %s", n.Slug, n.Pin.Endpoint, vr.Rule, vr.Reason)
		}
	}
	if len(installed) != len(top.Nodes) {
		t.Fatalf("the chain went back into %d of %d nodes: %v", len(installed), len(top.Nodes), installed)
	}
	if !r.saw("cp ") {
		t.Errorf("the chain never reached a node: the image has no shell, so it arrives by `docker cp`: %v", r.calls)
	}
}
