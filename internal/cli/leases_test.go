package cli

import (
	"context"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Two processes' keepers on one store: the first to ask holds each lease and the other does not;
// when the holder stops, it lets go at once, and the other takes the work at its next renewal —
// not LeaseTTL later, which is what a crash costs.
func TestTheBackgroundWorkPassesToAnotherProcessWhenItsHolderStops(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "leases.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a := newLeaseKeeper(st, "a", io.Discard, "retries", "retention")
	b := newLeaseKeeper(st, "b", io.Discard, "retries", "retention")
	a.renew(ctx)
	b.renew(ctx)
	for _, name := range []string{"retries", "retention"} {
		if !a.leading(name)(ctx) || b.leading(name)(ctx) {
			t.Fatalf("%s: a holds %v, b holds %v; want a alone", name, a.leading(name)(ctx), b.leading(name)(ctx))
		}
	}
	runCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { a.Run(runCtx) })
	stop()
	wg.Wait()
	b.renew(ctx)
	for _, name := range []string{"retries", "retention"} {
		if !b.leading(name)(ctx) {
			t.Fatalf("%s: the other process could not take the work its stopped holder let go", name)
		}
	}
}
