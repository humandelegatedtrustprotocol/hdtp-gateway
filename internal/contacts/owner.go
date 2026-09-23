package contacts

// The owner's side of the contact lifecycle (SPEC §9.1): approve, reject, block, unblock, remove,
// and the expiry of requests nobody answered. The portal and the owner MCP both call these, so the
// two surfaces cannot decide differently (§8.4) — they did: the portal's approve discarded the
// "they could not be told" notice the MCP returned, both told the peer a preset's bundle instead
// of the grant the row held, and neither could reject, block or unblock the same way.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// ErrWrongState: the contact exists and is not in a state the action applies to.
var ErrWrongState = errors.New("conflict")

// NotifyBudget bounds each courtesy call to a peer. The decision is local and already made; the
// call only tells them, so a peer that cannot be reached must not hold the owner's request — the
// portal POST or the agent's tool call — for the outbound client's thirty seconds.
const NotifyBudget = 5 * time.Second

// DefaultRequestExpiry is SPEC §9.1's default for an unanswered request.
const DefaultRequestExpiry = 30 * 24 * time.Hour

// Owner carries what the lifecycle needs beyond the store: dropping a caller's composed surface
// when its tier changes, and the calls that tell the peer. Each Tell* is best-effort and nil-safe:
// nil means the peer is not told, and the result says so.
type Owner struct {
	Manager    *Manager
	Invalidate func(ctx context.Context, accountID, fpr string) error
	// TellApproved sends `contact_accepted` with what we granted them.
	TellApproved func(ctx context.Context, accountID, fpr string, granted []string) error
	// TellRejected sends `contact_rejected` (PACT §5.1: the rejecting side MAY; a requester left
	// at pending_out for ever is the alternative).
	TellRejected func(ctx context.Context, accountID, fpr string) error
	// TellRemoved calls the contact's `remove_contact` (§9.1: removal notifies and unpins both sides).
	TellRemoved func(ctx context.Context, accountID, fpr string) error
}

// Decision is what an owner action did.
type Decision struct {
	// Status is the relationship afterwards: active, blocked, or none when the row went.
	Status string `json:"status"`
	// Granted is what the row grants the contact after an approval — read back from the row, so
	// it is what they were told, whatever the approval did or did not name.
	Granted []string `json:"granted,omitempty"`
	// Told reports whether the peer heard, for the actions that tell them. Unreachable is Why.
	Told bool   `json:"told"`
	Why  string `json:"why,omitempty"`
}

func (o Owner) invalidate(ctx context.Context, accountID, fpr string) {
	if o.Invalidate != nil {
		_ = o.Invalidate(ctx, accountID, fpr)
	}
}

// tell runs one courtesy call inside NotifyBudget and records the outcome on d.
func tell(ctx context.Context, d *Decision, call func(ctx context.Context) error) {
	if call == nil {
		d.Why = "this node has no way to reach them"
		return
	}
	nctx, cancel := context.WithTimeout(ctx, NotifyBudget)
	defer cancel()
	if err := call(nctx); err != nil {
		d.Why = err.Error()
		return
	}
	d.Told = true
}

func (o Owner) row(ctx context.Context, accountID, fpr string) (store.Contact, error) {
	c, err := o.Manager.Store.GetContact(ctx, accountID, fpr)
	if err != nil {
		return c, fmt.Errorf("%w: no such contact", ErrUnknownContact)
	}
	return c, nil
}

// Approve accepts a waiting request (pending_in → active). A named preset replaces the grant with
// that bundle, and an unknown name is refused before anything is written. No preset keeps the
// grant the row already holds — a request that came through an invite holds the invite's — and
// the peer is told that grant, the one the row has, not a bundle nobody applied.
func (o Owner) Approve(ctx context.Context, accountID, fpr, preset string) (Decision, error) {
	c, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	if c.Status != "pending_in" {
		return Decision{}, fmt.Errorf("%w: that contact is %s, not a waiting request", ErrWrongState, c.Status)
	}
	var bundle []string
	if preset != "" {
		perms, ok := LoadPresets(ctx, o.Manager.Store)[preset]
		if !ok {
			return Decision{}, fmt.Errorf("%w: there is no preset called %q", ErrBadRequest, preset)
		}
		bundle = perms
	}
	err = o.Manager.Store.Atomically(ctx, func(tx store.Store) error {
		if err := tx.UpdateContactStatus(ctx, accountID, fpr, "active"); err != nil {
			return err
		}
		if preset != "" {
			return tx.UpdateContactPermissions(ctx, accountID, fpr, bundle, preset)
		}
		return nil
	})
	if err != nil {
		return Decision{}, err
	}
	o.invalidate(ctx, accountID, fpr)
	now, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Status: "active", Granted: now.Permissions}
	var call func(context.Context) error
	if o.TellApproved != nil {
		call = func(ctx context.Context) error { return o.TellApproved(ctx, accountID, fpr, now.Permissions) }
	}
	tell(ctx, &d, call)
	return d, nil
}

// Reject declines a waiting request: a demotion, not a deletion (PACT §5.1). The row moves to
// blocked, so that root's next request is answered as a stranger's and never reaches the owner,
// and the peer is told so it does not wait at pending_out for ever. A row already blocked is the
// outcome asked for and nothing is sent.
func (o Owner) Reject(ctx context.Context, accountID, fpr string) (Decision, error) {
	c, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	if c.Status == "blocked" {
		return Decision{Status: "blocked"}, nil
	}
	if c.Status != "pending_in" {
		return Decision{}, fmt.Errorf("%w: that contact is %s, not a waiting request", ErrWrongState, c.Status)
	}
	if err := o.Manager.Store.UpdateContactStatus(ctx, accountID, fpr, "blocked"); err != nil {
		return Decision{}, err
	}
	o.invalidate(ctx, accountID, fpr)
	d := Decision{Status: "blocked"}
	var call func(context.Context) error
	if o.TellRejected != nil {
		call = func(ctx context.Context) error { return o.TellRejected(ctx, accountID, fpr) }
	}
	tell(ctx, &d, call)
	return d, nil
}

// Block demotes any relationship to blocked, silently (SPEC §9.1, PACT §5.2): the peer is served
// the guest tier and is told nothing. A row already blocked is left as it is.
func (o Owner) Block(ctx context.Context, accountID, fpr string) (Decision, error) {
	c, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	if c.Status != "blocked" {
		if err := o.Manager.Store.UpdateContactStatus(ctx, accountID, fpr, "blocked"); err != nil {
			return Decision{}, err
		}
		o.invalidate(ctx, accountID, fpr)
	}
	return Decision{Status: "blocked"}, nil
}

// Unblock undoes a block, silently as the block was. A contact that was ever active returns to
// active with its grant, trust and pin as they were (`blocked --> active`). A row that never was —
// a request the owner rejected, or an approach of ours they declined — is forgotten: they are a
// stranger again and may ask again, which is the only truthful inverse of a rejection; restoring
// it to active would make a contact of somebody nobody approved. Status says which happened.
func (o Owner) Unblock(ctx context.Context, accountID, fpr string) (Decision, error) {
	c, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	if c.Status != "blocked" {
		return Decision{}, fmt.Errorf("%w: that contact is %s, not blocked", ErrWrongState, c.Status)
	}
	d := Decision{Status: "active"}
	if c.EverActive {
		err = o.Manager.Store.UpdateContactStatus(ctx, accountID, fpr, "active")
	} else {
		d.Status = "none"
		err = o.Manager.Store.DeleteContact(ctx, accountID, fpr)
	}
	if err != nil {
		return Decision{}, err
	}
	o.invalidate(ctx, accountID, fpr)
	return d, nil
}

// Remove ends a relationship in any state (`--> none`). An active contact is told first — the
// outbound call needs the row — and the local delete proceeds whatever they answer (PACT §5.2:
// enforcement is "your root is no longer in my list"). Any other row goes silently: a waiting
// request withdrawn, our own approach withdrawn, a blocked root forgotten.
func (o Owner) Remove(ctx context.Context, accountID, fpr string) (Decision, error) {
	c, err := o.row(ctx, accountID, fpr)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Status: "none"}
	if c.Status == "active" {
		var call func(context.Context) error
		if o.TellRemoved != nil {
			call = func(ctx context.Context) error { return o.TellRemoved(ctx, accountID, fpr) }
		}
		tell(ctx, &d, call)
	}
	if err := o.Manager.Store.DeleteContact(ctx, accountID, fpr); err != nil {
		return Decision{}, err
	}
	o.invalidate(ctx, accountID, fpr)
	return d, nil
}

// ExpireRequests removes the account's requests, theirs and ours, that nobody answered within
// window (SPEC §9.1): the relationship returns to none, and whoever asked may ask again.
func (o Owner) ExpireRequests(ctx context.Context, accountID string, window time.Duration) ([]store.ExpiredContact, error) {
	if window <= 0 {
		window = DefaultRequestExpiry
	}
	gone, err := o.Manager.Store.DeleteExpiredPendingContacts(ctx, accountID, o.Manager.now().Add(-window).Unix())
	if err != nil {
		return nil, err
	}
	for _, g := range gone {
		// Our own approach expiring changes the tier that caller is served at.
		o.invalidate(ctx, accountID, g.Fingerprint)
	}
	return gone, nil
}

// Offered is a contact's switchboard: the core permissions, whatever this account's surface
// currently gates a tool with (an integration's integration.<slug>, SPEC §6.4), and anything the
// contact already holds, so a save cannot drop a grant the owner never touched. It is the row list
// the portal renders and the allow-list both surfaces save against — the owner MCP used to save
// against the core five alone and answered "ok" for an integration grant it had thrown away.
func Offered(served, held []string) []string {
	out := append([]string{}, AllPermissions...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[p] = true
	}
	for _, ps := range [][]string{served, held} {
		for _, p := range ps {
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
