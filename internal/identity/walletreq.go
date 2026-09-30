package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// ErrLeafRefused marks an answer from a wallet that this host refused: no request pending, a chain
// that does not validate to the account's root at the pending endpoint, a leaf over another key, or
// one that is not newer than the current leaf. The install doors audit it as a refusal, not a failure.
var ErrLeafRefused = errors.New("leaf refused")

// ErrEndpointRefused marks a signing request refused for its endpoint: an address PACT's address
// rule refuses (pactidentity.AddressGuard), which no wallet would certify. It comes with
// ErrLeafRefused.
var ErrEndpointRefused = errors.New("the endpoint is not an address a wallet certifies")

// ErrRequestState marks an answer that does not carry the pending request's state, or carries one
// already used (PACT §9.1). It is a refusal too, and says the request is not in the state the answer
// assumes. Two of its cases come with a sentinel of their own (ErrRequestAnswered, ErrNoRequest);
// without either, a request IS pending and the answer is not for it (a request that was replaced,
// or one this identity never had).
var ErrRequestState = errors.New("the answer's state is not a pending request's")

// ErrRequestAnswered marks an answer whose state was installed already: the leaf it installed keeps
// the state's hash (store.Leaf.AnsweredStateHash). It comes with ErrRequestState.
var ErrRequestAnswered = errors.New("the answer was installed already")

// ErrNoRequest marks an answer that arrived when no request was pending and that was never
// installed here. It comes with ErrRequestState.
var ErrNoRequest = errors.New("no certificate request is pending")

// The chain refusals a person can act on, each with ErrLeafRefused: a leaf under a root other than
// the identity's (another wallet), over a key other than the request's, or not newer than the
// current leaf (PACT §14.3). Any other refusal of the chain is ErrLeafRefused alone.
var (
	ErrWrongRoot = errors.New("the chain's root is not this identity's")
	ErrWrongKey  = errors.New("the leaf carries another key than the request's")
	ErrNotNewer  = errors.New("the leaf is not newer than the current one")
)

// newRequestState is 32 random bytes, base64url without padding: the 43 characters a signing
// request's `state` must be.
func newRequestState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stateHash(state string) []byte {
	sum := sha256.Sum256([]byte(state))
	return sum[:]
}

// departedFrom is the leaf an install would follow: the current one, or, with none, the last leaf
// the ledger remembers (a pending request is not one). nil when the ledger holds no leaf at all.
func departedFrom(leaves []store.Leaf) *store.Leaf {
	var last *store.Leaf
	for i := range leaves {
		l := &leaves[i]
		if l.State == LeafCurrent {
			return l
		}
		if l.State == LeafPending || len(l.Leaf) == 0 || l.Endpoint == "" {
			continue
		}
		if last == nil || l.NotBefore >= last.NotBefore {
			last = l
		}
	}
	return last
}

// moves reports whether a leaf naming `endpoint` puts the identity at an address its contacts do
// not know (PACT §5.3, §9). It is the one rule for it: InstallLeaf reports it as InstallResult.Moved
// and starts the campaign on it, and WalletPurpose asks the wallet for a move on it.
//
//   - no root yet: a signup, not a move;
//   - a current leaf, or a ledger that remembers one: a move when the last one named another address;
//   - a root and no ledger at all: it arrived from another host with its name and nothing else.
func moves(a store.Account, leaves []store.Leaf, endpoint string) bool {
	if !a.HasRoot() {
		return false
	}
	prev := departedFrom(leaves)
	return prev == nil || prev.Endpoint != endpoint
}

// WalletPurpose is the purpose a signing request to a web wallet carries for this endpoint: `move`
// when a leaf there would move the identity, `renew` otherwise. An account with no root is refused:
// its first leaf is a signup, which the web wallet does not take.
func (m *Manager) WalletPurpose(ctx context.Context, accountID, endpoint string) (string, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return "", err
	}
	if !a.HasRoot() {
		return "", fmt.Errorf("identity: %s has no root yet; its first leaf comes from the CLI wallet (`account csr`, `pact id issue`, `account install-leaf`): %w", a.Slug, ErrLeafRefused)
	}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return "", err
	}
	if moves(a, leaves, endpoint) {
		return PurposeMove, nil
	}
	return PurposeRenew, nil
}

// MoveNotice is what a host says after an install that moved the identity (the identity-boundary
// design, §3), or "" when it did not move.
//
// Two moves reach it, and they are told apart by whether this node held the current leaf (OldKid):
//   - from another host (after an import): the old host is elsewhere, and the person deletes the
//     identity there once the contacts are reached;
//   - to a new address on THIS node (its public URL changed): the "old host" is this node, and the
//     design's wording — "then delete the identity at the old host" — would have the person erase
//     the identity they just moved (`account leave`). The superseded leaf goes on answering here
//     until its notAfter with nobody acting, so there is nothing to delete.
//
// The date is the leaf it follows, when this host's ledger knows one; after an import that carried
// no ledger it does not, and the notice says so rather than give one.
func MoveNotice(res InstallResult) string {
	if !res.Moved {
		return ""
	}
	until := "until it expires (this node's ledger does not hold its date)"
	if !res.OldNotAfter.IsZero() {
		until = "until " + res.OldNotAfter.UTC().Format(time.RFC3339)
	}
	announce := "Run `pact-gateway account announce -slug " + res.Slug + "` until none are waiting"
	if res.OldKid != "" {
		return "This node goes on answering at " + res.OldEndpoint + " with the previous certificate " + until +
			", for contacts not yet reached. " + announce + "."
	}
	return "The old host's certificate stays valid " + until + " for contacts not yet reached. " + announce +
		", then delete the identity at the old host."
}
