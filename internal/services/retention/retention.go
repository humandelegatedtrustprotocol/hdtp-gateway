// Package retention is the retention sweeper (SPEC §7.9): unlimited by default, and when an owner
// sets a window, messages and their orphaned blobs past it are deleted locally.
// The same pass expires contact requests nobody answered (SPEC §9.1).
//
// It runs on a slow ticker rather than on every write. Retention is a policy
// about age, not a reaction to an event, and a sweep that ran constantly would
// spend more time asking than deleting.
package retention

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
)

// SweepInterval is how often retention is applied. An hour is far finer than any
// realistic window and cheap: with no window set, a sweep removes no message, and what it does
// remove — records past their own window — it finds through an index on their expiry.
const SweepInterval = time.Hour

// Windows is what a pass reads of the owner's settings, per account: how long an unanswered
// request waits, and the retention window (zero is unlimited). *settings.Service is one.
type Windows interface {
	RequestExpiryFor(ctx context.Context, accountID string) time.Duration
	StorageFor(ctx context.Context, accountID string) (quota int64, retention time.Duration)
}

// Run applies retention every SweepInterval, once at startup first.
//
// The same tick retires expired leaves (`retireLeaves`, the node's own pass): a leaf's key is
// destroyed when the leaf runs out, and "when" has to mean within the hour on a node that is up,
// not at its next restart. It rides this ticker rather than having one of its own because it is
// the same kind of work — a policy about age — and it is nil-safe for callers with no node.
//
// The same tick archives the audit trail of the identities that left long enough ago
// (`archiveTrail`, audit.Departed via serve): a policy about age as well, nil-safe likewise.
//
// It BLOCKS until ctx ends, and it never returns while a pass is running. `serve` runs it in its
// background group and waits for that group before returning, so the store is not closed under a
// pass. It used to start a goroutine of its own and return at once, and nothing ever waited for it.
// ChangeLogKept is how long a change-log row is kept.
const ChangeLogKept = 7 * 24 * time.Hour

func Run(ctx context.Context, settings Windows, st store.Store,
	cfg *core.Config, auditFn func(action, resource, outcome string), stderr io.Writer, retireLeaves func(context.Context),
	archiveTrail func(context.Context), invalidate func(ctx context.Context, accountID, fpr string) error,
	leading func(context.Context) bool) {

	blobs := messaging.BlobDir{Root: cfg.Blobs()}
	requests := contacts.Owner{Manager: &contacts.Manager{Store: st}, Invalidate: invalidate}
	sweeper := &messaging.Sweeper{Store: st, Blobs: blobs, Audit: auditFn}

	// A pass cut short because the node is stopping has not failed. Its store calls return the
	// context's error, and printing those put "retention: …: context canceled" in front of an owner
	// whose store was fine — after `serve` had returned, until it began waiting for this function.
	report := func(what string, err error) {
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(stderr, "retention: %s: %v\n", what, err)
		}
	}
	sweep := func() {
		// One node process on the store sweeps (SPEC §11.1); the others, not holding the lease,
		// leave the pass to it. nil leads always: one process, or a test.
		if leading != nil && !leading(ctx) {
			return
		}
		if retireLeaves != nil {
			retireLeaves(ctx)
		}
		if archiveTrail != nil {
			archiveTrail(ctx)
		}
		// Whatever any account's window is: the records whose OWN window has closed. A sealed call
		// writes an idempotency record every time, and one past its window protects nothing (PACT
		// §13.3); an abandoned owner session is never presented again, so nothing else removes it.
		now := time.Now().Unix()
		_, err := st.DeleteExpiredIdempotency(ctx, now)
		report("idempotency records", err)
		_, err = st.DeleteExpiredSessions(ctx, now)
		report("sessions", err)
		// An address an identity left is reserved until the last leaf issued for it expires (PACT §9);
		// past that the row reserves nothing, and it names the address and nothing else.
		_, err = st.DeleteExpiredVacatedAddresses(ctx, now)
		report("vacated addresses", err)
		// The change log wakes waiters (SPEC §7.8); a change a week old has woken everyone it
		// ever will, and a cursor older than the log is answered as such (wait_for_updates).
		_, err = st.DeleteChangesBefore(ctx, now-int64(ChangeLogKept/time.Second))
		report("change log", err)
		accounts, err := st.ListAccounts(ctx)
		if err != nil {
			return
		}
		for _, a := range accounts {
			// SPEC §9.1: a request nobody answered, theirs or ours, expires, and the relationship
			// returns to none. Audited per row, because the owner never pressed anything.
			gone, err := requests.ExpireRequests(ctx, a.ID, settings.RequestExpiryFor(ctx, a.ID))
			report(a.Slug+" requests", err)
			for _, g := range gone {
				auditFn("contact_expire", "account:"+a.ID+" contact:"+g.Fingerprint+" status:"+g.Status, "ok")
			}
			_, window := settings.StorageFor(ctx, a.ID)
			if window <= 0 {
				continue // unlimited: the default, and it deletes nothing
			}
			_, err = sweeper.Sweep(ctx, a.ID, window)
			report(a.Slug, err)
		}
	}
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
}
