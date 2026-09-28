package cli

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// LeaseRenew is how often a process renews the background work's leases, and LeaseTTL how long
// each renewal holds one: a holder that stops without letting go — a crash — is replaced within
// LeaseTTL, one that stops cleanly at once (SPEC §11.1).
const (
	LeaseRenew = 10 * time.Second
	LeaseTTL   = 3 * LeaseRenew
)

// leaseKeeper holds this process's share of the leases on background work that only one node
// process on the store may run at a time: the outbound retries and the retention pass. It takes or
// renews every one on a clock of its own, independent of how often the work runs, and the work asks
// it whether this process holds its lease.
type leaseKeeper struct {
	st     store.LeaseStore
	holder string
	names  []string
	stderr io.Writer

	mu   sync.Mutex
	held map[string]bool
}

func newLeaseKeeper(st store.LeaseStore, holder string, stderr io.Writer, names ...string) *leaseKeeper {
	return &leaseKeeper{st: st, holder: holder, names: names, stderr: stderr, held: map[string]bool{}}
}

// renew takes or renews each lease once.
func (k *leaseKeeper) renew(ctx context.Context) {
	now := time.Now()
	for _, name := range k.names {
		held, err := k.st.TakeLease(ctx, name, k.holder, now.Unix(), now.Add(LeaseTTL).Unix())
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(k.stderr, "lease %s: %v\n", name, err)
		}
		k.mu.Lock()
		k.held[name] = held // a store that cannot answer is not a lease held
		k.mu.Unlock()
	}
}

// Run renews the leases every LeaseRenew until ctx ends, then lets go of every one it holds.
func (k *leaseKeeper) Run(ctx context.Context) {
	t := time.NewTicker(LeaseRenew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			release := context.WithoutCancel(ctx)
			for _, name := range k.names {
				if k.holds(name) {
					_ = k.st.ReleaseLease(release, name, k.holder)
				}
			}
			return
		case <-t.C:
			k.renew(ctx)
		}
	}
}

func (k *leaseKeeper) holds(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.held[name]
}

// leading is what a loop asks before it runs: whether this process holds the named lease now.
func (k *leaseKeeper) leading(name string) func(context.Context) bool {
	return func(context.Context) bool { return k.holds(name) }
}
