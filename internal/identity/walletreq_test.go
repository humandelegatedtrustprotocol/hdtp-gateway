package identity

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

const endpointB = "https://node.alina.example/a/alina/mcp"

// PACT §9.1: "A host MUST accept an answer only once, only with the state it minted for a pending
// request, and only a chain whose leaf carries that request's key and validates at its endpoint."
// Each refusal, then the one answer that must pass, then the same answer again.
func TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	first, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, first, now, 365), now); err != nil {
		t.Fatal(err)
	}

	later := now.Add(time.Minute)
	if _, err := m.IssueWalletCSR(ctx, a.ID, PurposeSignup, endpointA, "https://ceremony.pact.contact", later); !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("a web wallet was asked for a signup: %v", err)
	}
	req, err := m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://ceremony.pact.contact", later)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(req.State) {
		t.Fatalf("state %q is not 32 bytes of base64url", req.State)
	}
	leaves, _ := m.Store.ListLeaves(ctx, a.ID)
	for _, l := range leaves {
		if l.State == LeafPending {
			if l.WalletOrigin != "https://ceremony.pact.contact" || len(l.RequestStateHash) != 32 || strings.Contains(string(l.RequestStateHash), req.State) {
				t.Fatalf("the pending request keeps %q and %x: want the wallet and the state's hash, never the state", l.WalletOrigin, l.RequestStateHash)
			}
		}
	}
	good := w.issue(t, req, later, 365)

	// Another state, and no state at all.
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, strings.Repeat("A", 43), later); !errors.Is(err, ErrRequestState) {
		t.Fatalf("an answer with another state: %v", err)
	}
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, "", later); !errors.Is(err, ErrRequestState) {
		t.Fatalf("an answer with no state: %v", err)
	}
	// The wrong key: a leaf the wallet issued over some other request.
	other, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, later) // replaces the pending request...
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := w.issue(t, other, later, 365)
	req, err = m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://ceremony.pact.contact", later) // ...and this one replaces it again
	if err != nil {
		t.Fatal(err)
	}
	good = w.issue(t, req, later, 365)
	if _, err := m.InstallWalletLeaf(ctx, a.ID, wrongKey, req.State, later); !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("a leaf over another key: %v", err)
	}
	// The wrong root: the right request, signed by somebody else's root.
	mallory := newWallet(t, "Mallory")
	if _, err := m.InstallWalletLeaf(ctx, a.ID, mallory.issue(t, req, later, 365), req.State, later); !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("a leaf under another root: %v", err)
	}
	// The state is judged before the chain: an answer with another state is refused for that,
	// whatever its chain, so an answer meant for no request here learns nothing about the chain rules.
	if _, err := m.InstallWalletLeaf(ctx, a.ID, wrongKey, strings.Repeat("B", 43), later); !errors.Is(err, ErrRequestState) || errors.Is(err, ErrLeafRefused) {
		t.Fatalf("another state over a bad chain was judged by its chain: %v", err)
	}
	// A refused chain does not use the state up: the right answer still goes in, once.
	res, err := m.InstallWalletLeaf(ctx, a.ID, good, req.State, later)
	if err != nil {
		t.Fatalf("the answer that must pass: %v", err)
	}
	if res.Kid != req.Kid || res.Moved {
		t.Fatalf("installed %+v", res)
	}
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, req.State, later); !errors.Is(err, ErrRequestState) {
		t.Fatalf("the same answer twice: %v", err)
	}
}

// Two answers carrying one state that arrive together: the check and the consumption are one
// statement, so exactly one is installed.
func TestTheStateIsConsumedByTheStatementThatChecksIt(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	req, err := m.IssueWalletCSR(ctx, a.ID, PurposeMove, endpointA, "https://w.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := stateHash(req.State)
	ok1, err := m.Store.ConsumeLeafRequest(ctx, a.ID, req.Kid, h)
	if err != nil || !ok1 {
		t.Fatalf("first: %v %v", ok1, err)
	}
	if ok2, _ := m.Store.ConsumeLeafRequest(ctx, a.ID, req.Kid, h); ok2 {
		t.Fatal("the state was consumed twice")
	}
}

// The purpose a web wallet is asked for and whether the install then moves are one rule (moves):
// a renewal at the address the leaf names does not move; another address does; an account with no
// root is not asked at all.
func TestWalletPurposeIsTheRuleTheInstallMovesBy(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	if _, err := m.WalletPurpose(ctx, a.ID, endpointA); !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("no root: %v", err)
	}
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	csr, _ := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now); err != nil {
		t.Fatal(err)
	}
	for i, ep := range []string{endpointA, endpointB} {
		later := now.Add(time.Duration(i+1) * time.Minute)
		purpose, err := m.WalletPurpose(ctx, a.ID, ep)
		if err != nil {
			t.Fatal(err)
		}
		req, err := m.IssueWalletCSR(ctx, a.ID, purpose, ep, "https://w.example", later)
		if err != nil {
			t.Fatal(err)
		}
		res, err := m.InstallWalletLeaf(ctx, a.ID, w.issue(t, req, later, 365), req.State, later)
		if err != nil {
			t.Fatal(err)
		}
		if res.Moved != (purpose == PurposeMove) {
			t.Fatalf("%s: asked for %s and the install says moved=%v", ep, purpose, res.Moved)
		}
		if ep == endpointB && (purpose != PurposeMove || MoveNotice(res) == "" || !strings.Contains(MoveNotice(res), res.OldNotAfter.UTC().Format(time.RFC3339))) {
			t.Fatalf("a move to %s: purpose %s, notice %q", ep, purpose, MoveNotice(res))
		}
		if ep == endpointA && MoveNotice(res) != "" {
			t.Fatalf("a renewal gave a move notice: %q", MoveNotice(res))
		}
	}
}

// After an import that carried no ledger there is no date to give, and the notice says so.
func TestAMoveNoticeWithNoLedgerGivesNoDate(t *testing.T) {
	n := MoveNotice(InstallResult{Moved: true, Slug: "alina"})
	if !strings.Contains(n, "does not hold its date") || !strings.Contains(n, "account announce -slug alina") {
		t.Fatalf("%q", n)
	}
	if MoveNotice(InstallResult{Slug: "alina"}) != "" {
		t.Fatal("a notice for an install that did not move")
	}
}
