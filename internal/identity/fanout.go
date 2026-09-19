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

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Campaign is what a fan-out needs: whose contacts, which leaf, and a name for the
// durable progress rows so two campaigns cannot be mistaken for each other.
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

// FanoutCall delivers the campaign to one contact.
type FanoutCall func(ctx context.Context, contact store.Contact, card string) error

// Fanout walks the account's active contacts, recording per-contact outcome
// durably; contacts already marked done for this campaign are skipped, so a
// re-run after an interruption resumes exactly where it stopped.
func (a *Announcer) Fanout(ctx context.Context, c Campaign, card string, call FanoutCall) (done, failed int, err error) {
	st := a.Manager.Store
	contacts, err := st.ListContacts(ctx, c.AccountID)
	if err != nil {
		return 0, 0, err
	}
	unrecorded := 0
	progress := map[string]store.RotationFanout{}
	if rows, err := st.ListRotationFanout(ctx, c.AccountID); err == nil {
		for _, row := range rows {
			progress[row.ContactFpr] = row
		}
	}
	for _, ct := range contacts {
		if ct.Status != "active" {
			continue
		}
		if p, ok := progress[ct.Fingerprint]; ok && p.NewFpr == c.NewKid && p.Status == "done" {
			done++
			continue
		}
		attempts := progress[ct.Fingerprint].Attempts + 1
		callErr := call(ctx, ct, card)
		status, lastErr := "done", ""
		if callErr != nil {
			status, lastErr = "pending", callErr.Error()
			failed++
		} else {
			done++
		}
		// This write IS the campaign's durability: "re-run to resume" means read these rows. Its
		// error was discarded, so a store that could not record progress looked exactly like one
		// that had, and the next run re-announced to everybody or — worse — believed a row that
		// was never written. A contact that was told is still told; what is lost is the record,
		// and that is said, once per contact and in the result.
		if uerr := st.UpsertRotationFanout(ctx, store.RotationFanout{
			AccountID: c.AccountID, ContactFpr: ct.Fingerprint, NewFpr: c.NewKid,
			Status: status, Attempts: attempts, LastError: lastErr, UpdatedAt: a.now().Unix(),
		}); uerr != nil {
			unrecorded++
			a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:progress not recorded", "error")
			continue
		}
		a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint, status)
	}
	switch {
	case unrecorded > 0:
		return done, failed, fmt.Errorf("identity: move fan-out could not record progress for %d contact(s); the store is refusing writes, and a re-run will announce to them again", unrecorded)
	case failed > 0:
		return done, failed, ErrFanoutIncomplete
	}
	return done, failed, nil
}
