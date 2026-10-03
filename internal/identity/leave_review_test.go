package identity

import (
	"context"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// racingStore commits one write just before the first transaction begins: an install that lands
// between what a leave read and when it erased.
type racingStore struct {
	store.Store
	race func()
}

func (r *racingStore) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	if r.race != nil {
		race := r.race
		r.race = nil
		race()
	}
	return r.Store.Atomically(ctx, fn)
}

// L2 (review 2026-09-28). What a leave reserves is decided from the leaves it reads; it read them
// before its transaction, so a leaf installed in between named an address the leave then left
// unreserved, free for another identity while that leaf was still live (HDTP §9).
func TestALeafInstalledJustBeforeTheLeaveIsReserved(t *testing.T) {
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
	inner := m.Store
	m.Store = &racingStore{Store: inner, race: func() {
		if err := inner.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:just-installed", Leaf: []byte("leaf"),
			NotBefore: now.Unix(), NotAfter: now.Add(400 * 24 * time.Hour).Unix(), State: LeafSuperseded, Endpoint: endpointB, CreatedAt: now.Unix()}); err != nil {
			t.Fatal(err)
		}
	}}
	res, err := m.Leave(ctx, a.ID, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	reserved := map[string]bool{}
	for _, v := range res.Vacated {
		reserved[v.Endpoint] = true
	}
	if !reserved[endpointA] || !reserved[endpointB] {
		t.Fatalf("reserved %v; the leaf installed a moment before the leave names %s", res.Vacated, endpointB)
	}
	if live, _ := inner.LiveVacatedEndpoint(ctx, endpointB, now.Unix()); !live {
		t.Fatalf("%s is not reserved on the store", endpointB)
	}
}
