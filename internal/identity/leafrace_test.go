package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// M3 (review 2026-09-28). One pending request at a time: a new one replaces the last. The
// replacement was three writes with no transaction — delete the pending row, insert the new one,
// record its state — so two requests started together could both delete nothing and both insert,
// leaving two pending rows, and an install then took whichever the loop met last.
func TestConcurrentRequestsLeaveOnePending(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	for round := 0; round < 25; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, 3)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, time.Now())
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: a request made beside another failed: %v", round, err)
			}
		}
		leaves, err := m.Store.ListLeaves(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		pending := 0
		for _, l := range leaves {
			if l.State == LeafPending {
				pending++
			}
		}
		if pending != 1 {
			t.Fatalf("round %d: %d pending requests, want one", round, pending)
		}
	}
}

// M4 (review 2026-09-28). Two answers carrying one state that pass every check together: the state
// is consumed by the statement that checks it, inside the install's transaction, so exactly one is
// installed. The barrier holds both answers after their checks and before either writes; without
// the consumption both would install. (TestTheStateIsConsumedByTheStatementThatChecksIt calls the
// store twice in a row, which no install does, so it could not fail on this.)
func TestTwoAnswersTogetherInstallOnce(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	req, err := m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://w.example", later)
	if err != nil {
		t.Fatal(err)
	}
	chain := w.issue(t, req, later, 365)
	var arrived sync.WaitGroup
	arrived.Add(2)
	m.beforeInstallWrites = func() { arrived.Done(); arrived.Wait() }
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := m.InstallWalletLeaf(ctx, a.ID, chain, req.State, later)
			errs <- err
		}()
	}
	var ok, stale int
	for i := 0; i < 2; i++ {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrRequestAnswered) && errors.Is(err, ErrRequestState):
			stale++
		default:
			t.Fatalf("an answer failed otherwise: %v", err)
		}
	}
	if ok != 1 || stale != 1 {
		t.Fatalf("two answers with one state: %d installed, %d refused as answered; want 1 and 1", ok, stale)
	}
}

// Coordinator (QA of 2026-09-28), item 2. A public_url of localhost made `account csr` mint a
// request for an endpoint no wallet certifies ("endpoint host is local"). The request is refused
// in the core's words, before a key is made for it.
func TestARequestForAnAddressNoWalletCertifiesIsRefused(t *testing.T) {
	m, a := leafEnv(t)
	for _, ep := range []string{"https://localhost/a/alina/mcp", "https://127.0.0.1:8443/a/alina/mcp", "https://10.0.0.7/a/alina/mcp"} {
		_, err := m.IssueCSR(context.Background(), a.ID, PurposeSignup, ep, time.Now())
		if !errors.Is(err, ErrLeafRefused) || !strings.Contains(err.Error(), "endpoint host is") {
			t.Fatalf("a request for %s: %v", ep, err)
		}
	}
	if leaves, _ := m.Store.ListLeaves(context.Background(), a.ID); len(leaves) != 0 {
		t.Fatalf("a refused request left %d ledger rows", len(leaves))
	}
}
