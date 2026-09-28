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

// Campaign is what a fan-out needs: whose contacts, which leaf is being announced, and what that
// leaf's install did. The leaf's kid is what the durable progress rows are matched on
// (`move_fanout.leaf_kid`), so a second move is a second campaign and cannot be mistaken for the
// tail of the first.
type Campaign struct {
	AccountID string
	NewKid    string
	// Moved is the install's decision that this leaf moved the identity (store.Leaf.Moved): a
	// move is news to every active contact. Any other leaf is news to nobody — a renewal reaches a
	// contact in the chain of the next envelope — and its campaign is only the handshake an import
	// left owed.
	Moved bool
	// RequestedAt is when this leaf was requested (store.Leaf.CreatedAt). A contact an import
	// wrote after that is owed the handshake by the identity's NEXT leaf, not by this one.
	RequestedAt int64
}

// CampaignFor is the campaign of one of the account's leaves, read from its ledger row: what a
// resumed walk needs to walk the same contacts the install's walk did.
func (m *Manager) CampaignFor(ctx context.Context, accountID, kid string) (Campaign, error) {
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return Campaign{}, err
	}
	for _, l := range leaves {
		if l.Kid == kid && len(l.Leaf) > 0 {
			return Campaign{AccountID: accountID, NewKid: kid, Moved: l.Moved, RequestedAt: l.CreatedAt}, nil
		}
	}
	return Campaign{}, fmt.Errorf("identity: no installed leaf %s: %w", kid, store.ErrNotFound)
}

// Owes says this campaign is the handshake a contact is owed (PACT §9.2): an import wrote it
// before this leaf was requested, it is not blocked, and it has not been told.
func (c Campaign) Owes(ct store.Contact) bool {
	return ct.Status != "blocked" && ct.HandshakeDue && ct.HandshakeDueAt <= c.RequestedAt
}

// Walks says whether the campaign reaches a contact: every one it owes the handshake, and, when
// the leaf moved the identity, every active contact, which pins this identity's root and is owed
// its new address (PACT §5.3, §9). A blocked contact is never called, whatever brought it. It is
// the one rule the walk, `account announce`'s ledger (node.MoveProgress) and the install's count
// all read.
func (c Campaign) Walks(ct store.Contact) bool {
	if ct.Status == "blocked" {
		return false
	}
	return c.Owes(ct) || (c.Moved && ct.Status == "active")
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
// outcome the audit row records (`updated`, `awaiting_approval`, `requested`, or FanoutRefused
// when the contact answered the handshake with a refusal). An error is a contact not told.
type FanoutCall func(ctx context.Context, contact store.Contact, card string) (outcome string, err error)

// FanoutRefused is the outcome, and the move_fanout status, of a contact that refused the
// handshake — update_contact and then request_contact — with an answer rather than a failure to
// arrive. It has answered: its mark is cleared and no run asks it again for this leaf.
const FanoutRefused = "refused"

// Fanout walks the contacts the campaign Walks, recording per-contact outcome
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
		if !c.Walks(ct) {
			continue
		}
		if len(ct.Leaf) == 0 {
			// A contact whose leaf this host does not hold — typically an imported one whose leaf
			// did not travel, or did not validate at its endpoint (export_read nulls it): nothing
			// can be sealed to it, and a stranger cannot fetch its card (get_card is
			// contact-tier). It stays pinned by its root and is reached when it next calls this
			// identity. The campaign records it as `unreached` once and does not call it
			// (PACT §9.2).
			if p, ok := progress[ct.Fingerprint]; ok && p.LeafKid == c.NewKid && p.Status == FanoutUnreached && !c.Owes(ct) {
				continue // already recorded for this leaf
			}
			if a.unreached(ctx, c, ct) {
				unrecorded++
			}
			continue
		}
		if p, ok := progress[ct.Fingerprint]; ok && p.LeafKid == c.NewKid && p.Status == "done" && !c.Owes(ct) {
			done++
			continue
		}
		if p, ok := progress[ct.Fingerprint]; ok && p.LeafKid == c.NewKid && p.Status == FanoutRefused {
			continue // it answered this leaf's handshake with a refusal: never asked again
		}
		attempts := progress[ct.Fingerprint].Attempts + 1
		outcome, callErr := call(ctx, ct, card)
		status, lastErr := "done", ""
		switch {
		case callErr != nil:
			status, lastErr, outcome = "pending", callErr.Error(), "pending"
			failed++
		case outcome == FanoutRefused:
			status, lastErr = FanoutRefused, "the handshake was refused"
		default:
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
		if status != "pending" && c.Owes(ct) {
			// Told, or answered with a refusal, so owed nothing more. A mark that will not clear
			// means the next campaign tells this contact again, which costs a call and harms
			// nothing; it is said.
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
// cleared when this campaign owed it one, and its audit row. It reports whether the record could
// not be written.
func (a *Announcer) unreached(ctx context.Context, c Campaign, ct store.Contact) (failed bool) {
	st := a.Manager.Store
	if err := st.UpsertMoveFanout(ctx, store.MoveFanout{
		AccountID: c.AccountID, ContactFpr: ct.Fingerprint, LeafKid: c.NewKid, Status: FanoutUnreached,
		Attempts: 0, LastError: "no leaf of theirs is held here", UpdatedAt: a.now().Unix(),
	}); err != nil {
		a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:progress not recorded", "error")
		return true
	}
	if c.Owes(ct) {
		if err := st.ClearContactHandshake(ctx, c.AccountID, ct.Fingerprint); err != nil {
			a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:handshake mark not cleared", "error")
			return true
		}
	}
	a.audit("account_move_fanout", "account:"+c.AccountID+" contact:"+ct.Fingerprint+" why:no leaf held", FanoutUnreached)
	return false
}

// HandshakesOwed counts the contacts an import brought that are owed this host's handshake and
// not blocked (PACT §9.2): what the campaign of the identity's next leaf will walk as the
// handshake. It is the one count `account certificate` and `doctor` read, so an owed handshake
// is never unseen; the install counts what its own leaf's campaign owes (Campaign.Owes).
func (m *Manager) HandshakesOwed(ctx context.Context, accountID string) (int, error) {
	held, err := m.Store.ListContacts(ctx, accountID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range held {
		if c.HandshakeDue && c.Status != "blocked" {
			n++
		}
	}
	return n, nil
}
