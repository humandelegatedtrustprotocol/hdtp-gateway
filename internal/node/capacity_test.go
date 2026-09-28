package node

// How many contact calls one account on one node serves in a second: the figure that caps the
// per-account aggregate (public.NodeCapacityPerSecond), measured rather than assumed.
//
// One node on its real listener, one account, N contacts each with its own root and leaf, pinned
// active. Each contact seals `send_message` to the account — the write path, the heaviest thing a
// contact does often — over TLS through the outbound client, at a rising offered rate spread across
// the contacts, open loop, for a few seconds per step. A step is served when at least 95% of what
// was offered completed without error and the p99 latency stayed under a second. The node's own
// budget is taken off for the run, since what is measured is what it can serve, not what it lets
// through.
//
// The callers run on the same machine as the node, and each call is a new MCP session over a new
// TLS connection sealing its own envelope, so the client side spends about what the node does: the
// figure is a floor for the node alone.
//
//   PACT_MEASURE_CAPACITY=1 GOWORK=off go test ./internal/node -run TestMeasureAccountCapacity -v -timeout 30m
//
// PACT_MEASURE_RATES="200,220,240" replaces the rising steps, and PACT_MEASURE_TOOL=get_card
// measures the read path instead of send_message.
//
// Without the variable the same machinery runs one small step (it is the hermetic guard of the
// measurement: tooling that only runs on demand goes stale silently otherwise).

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

type capacityStep struct {
	Offered, Done, Failed int
	Seconds               float64
	P50, P99              time.Duration
}

func (s capacityStep) served() bool {
	return s.Failed == 0 && float64(s.Done) >= 0.95*float64(s.Offered) && s.P99 < time.Second
}

func TestMeasureAccountCapacity(t *testing.T) {
	full := os.Getenv("PACT_MEASURE_CAPACITY") == "1"
	contactsN, rates, stepFor := 20, []int{40}, time.Second
	if full {
		contactsN, rates, stepFor = 500, []int{50, 100, 200, 300, 400, 500, 600, 800, 1000, 1200}, 5*time.Second
		if v := os.Getenv("PACT_MEASURE_RATES"); v != "" {
			rates = nil
			for _, f := range strings.Split(v, ",") {
				r, err := strconv.Atoi(strings.TrimSpace(f))
				if err != nil || r <= 0 {
					t.Fatalf("PACT_MEASURE_RATES: %q is not a rate", f)
				}
				rates = append(rates, r)
			}
		}
	}
	tool := "send_message"
	if v := os.Getenv("PACT_MEASURE_TOOL"); v != "" {
		tool = v
	}
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	acct := accts[0]
	n, base := e.start(e.options())
	// What the node can serve, not what its budget lets through.
	n.mu.RLock()
	n.accounts[acct.ID].pool.Limit = nil
	n.mu.RUnlock()
	peer, dial := e.peerFor(acct, base)
	peer.Seal = "required"

	clients := make([]*outbound.Client, contactsN)
	for i := range clients {
		kp := contactKeypair(t, fmt.Sprintf("https://c%d.example/a/c%d/mcp", i, i))
		root, _ := pactidentity.Parse(kp.Root)
		leaf, _ := pactidentity.Parse(kp.Leaf)
		if _, err := e.st.InsertContact(ctx, store.Contact{
			AccountID: acct.ID, Fingerprint: pactidentity.Fingerprint(root.SPKI), SPKI: leaf.SPKI, Status: "active",
			Permissions: []string{"message.text"}, Endpoint: leaf.URIs[0], Leaf: kp.Leaf, RootCert: kp.Root,
		}); err != nil {
			t.Fatal(err)
		}
		clients[i] = &outbound.Client{Keypair: kp, Cert: tls.Certificate{Certificate: [][]byte{kp.Leaf, kp.Root}, PrivateKey: kp.Signer}, DialContext: dial}
	}

	var seq atomic.Int64
	var results []capacityStep
	for _, rate := range rates {
		step := runStep(ctx, clients, peer, tool, rate, stepFor, &seq)
		results = append(results, step)
		t.Logf("%s offered %4d/s for %v: done %5d of %5d (%.0f/s), failed %d, p50 %v, p99 %v, served=%v",
			tool, rate, stepFor, step.Done, step.Offered, float64(step.Done)/step.Seconds, step.Failed, step.P50.Round(time.Millisecond), step.P99.Round(time.Millisecond), step.served())
		if !step.served() {
			break
		}
	}
	if !results[0].served() {
		t.Fatalf("the first step was not served: %+v", results[0])
	}
}

// runStep offers rate calls a second for d, each from the next contact in turn, and waits for them.
func runStep(ctx context.Context, clients []*outbound.Client, peer outbound.Peer, tool string, rate int, d time.Duration, seq *atomic.Int64) capacityStep {
	var (
		mu    sync.Mutex
		lat   []time.Duration
		fails int
		wg    sync.WaitGroup
	)
	interval := time.Second / time.Duration(rate)
	total := int(d / interval)
	start := time.Now()
	for i := range total {
		time.Sleep(time.Until(start.Add(time.Duration(i) * interval)))
		c := clients[i%len(clients)]
		id := seq.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			at := time.Now()
			msg := fmt.Sprintf("load-%d", id)
			args := map[string]any{}
			if tool == "send_message" {
				args = map[string]any{"msg_id": msg, "text": "load"}
			}
			res, err := c.SealedCall(cctx, peer, tool, args, msg)
			took := time.Since(at)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || res.IsError {
				fails++
				return
			}
			lat = append(lat, took)
		}()
	}
	wg.Wait()
	s := capacityStep{Offered: total, Done: len(lat), Failed: fails, Seconds: time.Since(start).Seconds()}
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		s.P50, s.P99 = lat[len(lat)/2], lat[len(lat)*99/100]
	}
	return s
}

// contactKeypair is another person's host: its own root, and a leaf over a fresh key for endpoint.
func contactKeypair(t testing.TB, endpoint string) *identity.Keypair {
	t.Helper()
	rootKey, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Contact", Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := identity.ToLib(kp)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: "Contact", RootCN: "Contact", RootKey: rootKey, HostPub: lib.Public, Endpoint: endpoint,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	kp.Leaf, kp.Root = leaf, rc
	return kp
}
