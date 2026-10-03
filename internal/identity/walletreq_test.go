package identity

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

const endpointB = "https://node.alina.example/a/alina/mcp"

// HDTP §9.1: "A host MUST accept an answer only once, only with the state it minted for a pending
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
	if _, err := m.IssueWalletCSR(ctx, a.ID, PurposeSignup, endpointA, "https://ceremony.batondeck.com", later); !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("a web wallet was asked for a signup: %v", err)
	}
	req, err := m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://ceremony.batondeck.com", later)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(req.State) {
		t.Fatalf("state %q is not 32 bytes of base64url", req.State)
	}
	leaves, _ := m.Store.ListLeaves(ctx, a.ID)
	for _, l := range leaves {
		if l.State == LeafPending {
			if l.WalletOrigin != "https://ceremony.batondeck.com" || len(l.RequestStateHash) != 32 || strings.Contains(string(l.RequestStateHash), req.State) {
				t.Fatalf("the pending request keeps %q and %x: want the wallet and the state's hash, never the state", l.WalletOrigin, l.RequestStateHash)
			}
		}
	}
	good := w.issue(t, req, later, 365)

	// Another state, and no state at all.
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, strings.Repeat("A", 43), later); !errors.Is(err, ErrRequestState) || errors.Is(err, ErrRequestAnswered) || errors.Is(err, ErrNoRequest) {
		t.Fatalf("an answer with another state, a request pending: %v", err)
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
	req, err = m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://ceremony.batondeck.com", later) // ...and this one replaces it again
	if err != nil {
		t.Fatal(err)
	}
	good = w.issue(t, req, later, 365)
	if _, err := m.InstallWalletLeaf(ctx, a.ID, wrongKey, req.State, later); !errors.Is(err, ErrLeafRefused) || !errors.Is(err, ErrWrongKey) || errors.Is(err, ErrWrongRoot) {
		t.Fatalf("a leaf over another key: %v", err)
	}
	// The wrong root: the right request, signed by somebody else's root.
	mallory := newWallet(t, "Mallory")
	if _, err := m.InstallWalletLeaf(ctx, a.ID, mallory.issue(t, req, later, 365), req.State, later); !errors.Is(err, ErrLeafRefused) || !errors.Is(err, ErrWrongRoot) || errors.Is(err, ErrWrongKey) {
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
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, req.State, later); !errors.Is(err, ErrRequestState) || !errors.Is(err, ErrRequestAnswered) {
		t.Fatalf("the same answer twice: %v", err)
	}
	// With nothing pending, a state this identity never had is not one that was installed.
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, strings.Repeat("C", 43), later); !errors.Is(err, ErrRequestState) || !errors.Is(err, ErrNoRequest) || errors.Is(err, ErrRequestAnswered) {
		t.Fatalf("a state never minted, nothing pending: %v", err)
	}
	// A new request waiting does not make the answer installed before it "not for this request": it
	// is still the answer that was installed.
	if _, err := m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://ceremony.batondeck.com", later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallWalletLeaf(ctx, a.ID, good, req.State, later); !errors.Is(err, ErrRequestAnswered) {
		t.Fatalf("the installed answer again, another request pending: %v", err)
	}
}

// A leaf that is not newer than the current one is refused as that (HDTP §14.3), and a root that is
// not self-signed is a refused chain, not "another wallet's root".
func TestAWalletLeafNotNewerIsRefusedAsThat(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now().Add(-time.Hour).Truncate(time.Second)
	first, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, first, now, 365), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	req, err := m.IssueWalletCSR(ctx, a.ID, PurposeRenew, endpointA, "https://w.example", later)
	if err != nil {
		t.Fatal(err)
	}
	// The wallet dates the new leaf at the current one's notBefore: the same instant, not newer.
	same := req
	same.PreviousNotBefore = nil
	if _, err := m.InstallWalletLeaf(ctx, a.ID, w.issue(t, same, now, 365), req.State, later); !errors.Is(err, ErrNotNewer) || !errors.Is(err, ErrLeafRefused) {
		t.Fatalf("a leaf as old as the current one: %v", err)
	}
	// A root that is this identity's key but not self-signed: rule 2, and not the wrong root.
	chain := w.issue(t, req, later, 365)
	broken := append([]byte(nil), chain[1]...)
	broken[len(broken)-1] ^= 1 // the root's signature
	if _, err := m.InstallWalletLeaf(ctx, a.ID, [][]byte{chain[0], broken}, req.State, later); !errors.Is(err, ErrLeafRefused) || errors.Is(err, ErrWrongRoot) || !strings.Contains(err.Error(), "rule 2") {
		t.Fatalf("a root that is not self-signed: %v", err)
	}
	// And the request is still answerable.
	if _, err := m.InstallWalletLeaf(ctx, a.ID, chain, req.State, later); err != nil {
		t.Fatalf("the answer that must pass: %v", err)
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
	// The statement that consumed it kept it as the answered state (migration 0051).
	leaves, err := m.Store.ListLeaves(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves {
		if l.Kid == req.Kid && (len(l.RequestStateHash) != 0 || !bytes.Equal(l.AnsweredStateHash, h)) {
			t.Fatalf("after the answer: request %x answered %x, want none and %x", l.RequestStateHash, l.AnsweredStateHash, h)
		}
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
		// This node moved its own address: the old host is this node, and nothing is to be deleted.
		if ep == endpointB && (strings.Contains(MoveNotice(res), "delete") || !strings.Contains(MoveNotice(res), endpointA)) {
			t.Fatalf("a move within this node tells the person to delete it: %q", MoveNotice(res))
		}
		if ep == endpointA && MoveNotice(res) != "" {
			t.Fatalf("a renewal gave a move notice: %q", MoveNotice(res))
		}
	}
}

// After an import that carried no ledger there is no date to give, and the notice says so; the old
// host is elsewhere, so it is where the identity is deleted once the contacts are reached.
func TestAMoveNoticeWithNoLedgerGivesNoDate(t *testing.T) {
	n := MoveNotice(InstallResult{Moved: true, Slug: "alina"})
	if !strings.Contains(n, "does not hold its date") || !strings.Contains(n, "account announce -slug alina") ||
		!strings.Contains(n, "delete the identity at the old host") {
		t.Fatalf("%q", n)
	}
	if MoveNotice(InstallResult{Slug: "alina"}) != "" {
		t.Fatal("a notice for an install that did not move")
	}
}
