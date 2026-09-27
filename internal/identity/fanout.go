// The move campaign's fan-out (PACT §5.3, §9): telling every contact, once and
// durably, that this identity now answers at a new address.
//
// This file is what is left of `rotate.go`. That file performed PACT 1.x key
// rotation — a new key, a grace period in which both were live, a proof signed by
// the old key, and an `update_contact` walk over contacts pinned to a key. 2.0 has
// none of that: a root is never rotated, a renewal is a new leaf a contact learns
// from the chain the next envelope carries, and the only thing still worth walking
// every contact for is a MOVE, where the address in the leaf's SAN changed and
// nobody would otherwise know. So the walk survives and everything around it does
// not — and it is named for what it does rather than for what it used to be.
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// Campaign is what a fan-out needs: whose contacts, and which leaf is being announced. The
// leaf's kid is what the durable progress rows are matched on (`move_fanout.leaf_kid`), so a
// second move is a second campaign and cannot be mistaken for the tail of the first.
type Campaign struct {
	AccountID string
	NewKid    string
}

// ErrFanoutIncomplete says some contacts were not reached. It is the ordinary outcome of a walk
// over people who are not all online, not a fault: the counts say how many, and a re-run resumes.
var ErrFanoutIncomplete = errors.New("identity: move fan-out incomplete; re-run to resume")

// Announcer runs campaigns for a node's accounts.
type Announcer struct {
	Manager *Manager
	Audit   func(action, resource, outcome string)
	Now     func() time.Time
}

func (a *Announcer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Announcer) audit(action, resource, outcome string) {
	if a.Audit != nil {
		a.Audit(action, resource, outcome)
	}
}

// FanoutCall delivers the campaign to one contact, and names what became of it: the literal
// outcome the audit row records (`updated`, `awaiting_approval`, `requested`). An error is a
// contact not told.
type FanoutCall func(ctx context.Context, contact store.Contact, card string) (outcome string, err error)

// InCampaign says whether a contact is walked by the campaign: every active contact, which pins
// this identity's root and is owed its new address (PACT §5.3, §9), and every contact an import
// brought that is not blocked and has not heard from this host yet (PACT §9.2). A blocked contact
// is never called, whatever brought it.
func InCampaign(c store.Contact) bool {
	if c.Status == "blocked" {
		return false
	}
	return c.Status == "active" || c.HandshakeDue
}

// Fanout walks the contacts InCampaign names, recording per-contact outcome
// durably; contacts already marked done for this campaign are skipped, so a
// re-run after an interruption resumes exactly where it stopped. A contact an
// import brought is told once: its mark is cleared when it has been.
func (a *Announcer) Fanout(ctx context.Context, c Campaign, card string, call FanoutCall) (done, failed int, err error) {
	st := a.Manager.Store
	contacts, err := st.ListContacts(ctx, c.AccountID)
	if err != nil {
		return 0, 0, err
	}
	unrecorded := 0
	progress := map[string]store.MoveFanout{}
	if rows, err := st.ListMoveFanout(ctx, c.AccountID); err == nil {
		for _, row := range rows {
			progress[row.ContactFpr] = row
		}
	}
	for _, ct := range contacts {
		if !InCampaign(ct) {
			continue
		}
		if len(ct.Leaf) == 0 {
			// A contact whose leaf this host does not hold — typically an imported one whose leaf
			// did not travel, or did not validate at its endpoint (export_read nulls it): nothing
			// can be sealed to it, and a stranger cannot fetch its card (get_card is
			// contact-tier). It stays pinned by its root and is reached when it next calls this
			// identity. The campaign records it as `unreached` once and does not call it
			// (PACT §9.2).
			if p, ok := progress[ct.Fingerprint]; ok && p.LeafKid == c.NewKid && p.Status == FanoutUnreached && !ct.HandshakeDue {
				continue // already recorded for this leaf
			}
			if a.unreached(ctx, c, ct) {
				unrecorded++
			}
			continue
		}
		if p, ok := progress[ct.Fingerprint]; ok && p.LeafKid == c.NewKid && p.Status == "done" && !ct.HandshakeDue {
			done++
			continue
		}
		attempts := progress[ct.Fingerprint].Attempts + 1
		outcome, callErr := call(ctx, ct, card)
		status, lastErr := "done", ""
		if callErr != nil {
			status, lastErr, outcome = "pending", callErr.Error(), "pending"
			failed++
		} else {
			done++
		}
		// This write IS the campaign's durability: "re-run to resume" means read these rows. Its
		// error was discarded, so a store that could not record progress looked exactly like one
		// that had, and the next run re-announced to everybody or — worse — believed a row that
		// was never written. A contact that was told is still told; what is lost is the record,
		// and that is said, once per contact and in the result.
		if uerr := st.UpsertMoveFanout(ctx, store.MoveFanout{
			AccountID: c.AccountID, ContactFpr: ct.Fingerprint, LeafKid: c.NewKid,
			Status: status, Attempts: attempts, LastError: lastErr, UpdatedAt: a.now().Unix(),
		}); uerr != nil {
			unrecorded++
			a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:progress not recorded", "error")
			continue
		}
		if status == "done" && ct.HandshakeDue {
			// Told, so owed nothing more. A mark that will not clear means the next campaign
			// tells this contact again, which costs a call and harms nothing; it is said.
			if cerr := st.ClearContactHandshake(ctx, c.AccountID, ct.Fingerprint); cerr != nil {
				unrecorded++
				a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:handshake mark not cleared", "error")
				continue
			}
		}
		a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint, outcome)
	}
	switch {
	case unrecorded > 0:
		return done, failed, fmt.Errorf("identity: move fan-out could not record progress for %d contact(s); the store is refusing writes, and a re-run will announce to them again", unrecorded)
	case failed > 0:
		return done, failed, ErrFanoutIncomplete
	}
	return done, failed, nil
}

// FanoutUnreached is the move_fanout status of a contact a campaign could not reach at all,
// because this host holds no leaf of theirs to seal to.
const FanoutUnreached = "unreached"

// unreached records one contact whose leaf is not held: its progress row, its handshake mark
// cleared (a no-op for a contact that had none), and its audit row. It reports whether the record could not be written.
func (a *Announcer) unreached(ctx context.Context, c Campaign, ct store.Contact) (failed bool) {
	st := a.Manager.Store
	if err := st.UpsertMoveFanout(ctx, store.MoveFanout{
		AccountID: c.AccountID, ContactFpr: ct.Fingerprint, LeafKid: c.NewKid, Status: FanoutUnreached,
		Attempts: 0, LastError: "no leaf of theirs is held here", UpdatedAt: a.now().Unix(),
	}); err != nil {
		a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:progress not recorded", "error")
		return true
	}
	if err := st.ClearContactHandshake(ctx, c.AccountID, ct.Fingerprint); err != nil {
		a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:handshake mark not cleared", "error")
		return true
	}
	a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:no leaf held", FanoutUnreached)
	return false
}
