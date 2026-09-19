package cli

// The retention sweeper (SPEC §7.9): unlimited by default, and when an owner
// sets a window, messages and their orphaned blobs past it are deleted locally.
//
// It runs on a slow ticker rather than on every write. Retention is a policy
// about age, not a reaction to an event, and a sweep that ran constantly would
// spend more time asking than deleting.

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

// SweepInterval is how often retention is applied. An hour is far finer than any
// realistic window and cheap: with no window set, a sweep does nothing at all.
const SweepInterval = time.Hour

// The same tick retires expired leaves (`retireLeaves`, the node's own pass): a leaf's key is
// destroyed when the leaf runs out, and "when" has to mean within the hour on a node that is up,
// not at its next restart. It rides this ticker rather than having one of its own because it is
// the same kind of work — a policy about age — and it is nil-safe for callers with no node.
func startRetentionSweeper(ctx context.Context, settings *settingsService, st store.Store,
	cfg *core.Config, auditFn func(action, resource, outcome string), stderr io.Writer, retireLeaves func(context.Context)) {

	blobs := messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}
	sweeper := &messaging.Sweeper{Store: st, Blobs: blobs, Audit: auditFn}

	sweep := func() {
		if retireLeaves != nil {
			retireLeaves(ctx)
		}
		accounts, err := st.ListAccounts(ctx)
		if err != nil {
			return
		}
		for _, a := range accounts {
			_, window := settings.storageFor(ctx, a.ID)
			if window <= 0 {
				continue // unlimited: the default, and it deletes nothing
			}
			if _, err := sweeper.Sweep(ctx, a.ID, window); err != nil {
				fmt.Fprintf(stderr, "retention: %s: %v\n", a.Slug, err)
			}
		}
	}
	go func() {
		t := time.NewTicker(SweepInterval)
		defer t.Stop()
		sweep() // once at startup, so a window set while stopped takes effect
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweep()
			}
		}
	}()
}
