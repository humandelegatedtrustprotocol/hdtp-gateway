package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Two identities on one node, each with a web-wallet request waiting. An answer is accepted only by
// the account whose request minted its state: one identity's state, carried to the other, is
// refused as a state that is not that request's — never installed — and a leaf that carries the
// request's key but names another endpoint is refused by the chain rules (PACT §9.1: "only a chain
// whose leaf carries that request's key and validates at its endpoint"). The control: each
// identity's own answer, afterwards, goes in.
func TestAWalletAnswerCannotCrossIdentitiesOrEndpoints(t *testing.T) {
	m, alina := leafEnv(t)
	ctx := context.Background()
	bharat, err := m.CreateAccount(ctx, "bharat", "Bharat Iyer", AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const endpointBharat = "https://agent.bharat.example/a/bharat/mcp"
	wa, wb := newWallet(t, "Alina Rao"), newWallet(t, "Bharat Iyer")
	for _, c := range []struct {
		id, endpoint string
		w            *wallet
	}{{alina.ID, endpointA, wa}, {bharat.ID, endpointBharat, wb}} {
		first, err := m.IssueCSR(ctx, c.id, PurposeSignup, c.endpoint, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.InstallLeaf(ctx, c.id, c.w.issue(t, first, now, 365), now); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(time.Minute)
	reqA, err := m.IssueWalletCSR(ctx, alina.ID, PurposeRenew, endpointA, "https://w.example", later)
	if err != nil {
		t.Fatal(err)
	}
	reqB, err := m.IssueWalletCSR(ctx, bharat.ID, PurposeRenew, endpointBharat, "https://w.example", later)
	if err != nil {
		t.Fatal(err)
	}
	goodA, goodB := wa.issue(t, reqA, later, 365), wb.issue(t, reqB, later, 365)

	// Alina's whole answer, sent to Bharat's identity; each chain with the other's state.
	if _, err := m.InstallWalletLeaf(ctx, bharat.ID, goodA, reqA.State, later); !errors.Is(err, ErrRequestState) {
		t.Errorf("alina's answer and state at bharat's identity: %v", err)
	}
	if _, err := m.InstallWalletLeaf(ctx, alina.ID, goodB, reqA.State, later); !errors.Is(err, ErrLeafRefused) {
		t.Errorf("bharat's chain with alina's state at alina's identity: %v", err)
	}
	if _, err := m.InstallWalletLeaf(ctx, alina.ID, goodA, reqB.State, later); !errors.Is(err, ErrRequestState) {
		t.Errorf("alina's chain with bharat's state: %v", err)
	}

	// The request's own key, under the right root, naming an address that is not the request's.
	info := pactidentity.CSRCheck(reqA.CSR, [][]byte{wa.key.Public.SPKI})
	if !info.OK {
		t.Fatalf("the request does not read: %s", info.Why)
	}
	elsewhere, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: info.CN, RootCN: "Alina Rao", RootKey: wa.key, HostPub: info.Key, Endpoint: "https://elsewhere.example/a/alina/mcp",
		NotBefore: later.Add(-time.Minute).Truncate(time.Second), NotAfter: later.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallWalletLeaf(ctx, alina.ID, [][]byte{elsewhere, wa.root}, reqA.State, later); !errors.Is(err, ErrLeafRefused) {
		t.Errorf("a leaf over the request's key at another endpoint: %v", err)
	}

	// The controls: none of the refusals used a state up.
	if _, err := m.InstallWalletLeaf(ctx, alina.ID, goodA, reqA.State, later); err != nil {
		t.Errorf("alina's own answer: %v", err)
	}
	if _, err := m.InstallWalletLeaf(ctx, bharat.ID, goodB, reqB.State, later); err != nil {
		t.Errorf("bharat's own answer: %v", err)
	}
}
