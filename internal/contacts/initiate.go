package contacts

// The OWNER-initiated half of contact establishment (SPEC §9's
// `none --> pending_out`).
//
// Everything else here is the inbound half: a guest calls `redeem_invite` or
// `request_contact` on US, and lands `pending_in`. The outbound half was
// specified and never built — `pending_out` existed as a status and as a policy
// tier, and `ContactAccepted`/`ContactRejected` both require a row in it, but
// nothing wrote one. The consequence was that a node could only ever hold as
// contacts the agents that had called in; it could never reach out to a peer,
// which in turn meant relay-assisted delivery had no way to be set up at all.

import (
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Initiated records a contact the owner started: we called the peer's
// `redeem_invite` or `request_contact`, and this is what we keep locally.
//
// `accepted` is the peer's own answer — an invite with auto-accept returns
// `accepted` and grants permissions immediately, so there is nothing to wait
// for; anything else lands `pending_out` until they approve, at which point
// their `answer_request` reaches ContactAccepted.
//
// The two identity checks are not ceremony. The pin IS the identity (PACT §2),
// so recording a contact whose pinned key is not the key its card claims would
// let a tampered invite bind us to an attacker's key under the peer's name, and
// every later signature check would then pass for the wrong party.
func (m *Manager) Initiated(ctx context.Context, accountID, peerFpr, card string,
	spki []byte, accepted bool, permissions []string) error {

	if peerFpr == "" || len(spki) == 0 {
		return fmt.Errorf("%w: a contact needs a proven key", ErrIdentityRequired)
	}
	if CardKey(card) != peerFpr {
		return fmt.Errorf("%w: the card's certificate does not name the identity being pinned", ErrIdentityRequired)
	}
	if fingerprintOf(spki) != peerFpr {
		return fmt.Errorf("%w: the key does not hash to the fingerprint being pinned", ErrIdentityRequired)
	}
	// Always inserted pending_out, then moved on by the SAME transition a peer's
	// later approval takes. Reusing it rather than writing "active" directly is
	// deliberate: that path already validates the card against the identity and
	// already knows where the peer's grant belongs.
	if _, err := m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: peerFpr, SPKI: spki, Status: "pending_out",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
	}); err != nil {
		return fmt.Errorf("%w: already a contact or already pending", ErrBadRequest)
	}
	if !accepted {
		return nil
	}
	// THEIR permissions, not ours. `Permissions` is what we grant this contact on
	// OUR node; what the peer granted us is TheirPermissions. Putting the peer's
	// grant in the first field would hand them whatever they handed us — an
	// invite could then choose its own privileges on the machine that redeemed
	// it. We grant nothing here; that stays the owner's decision.
	return m.ContactAccepted(ctx, accountID, peerFpr, card, permissions)
}

// InitiatedByFingerprint is Initiated for the `request_contact` path, where we
// hold the peer's card and pin the root it names; the leaf and its key arrive with
// the first chain that validates (PACT §14.3).
func (m *Manager) InitiatedByFingerprint(ctx context.Context, accountID, peerFpr, card string) error {
	if peerFpr == "" {
		return fmt.Errorf("%w: a contact needs a fingerprint", ErrIdentityRequired)
	}
	if CardKey(card) != peerFpr {
		return fmt.Errorf("%w: the card's certificate does not name the identity being pinned", ErrIdentityRequired)
	}
	if _, err := m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: peerFpr, Status: "pending_out",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
	}); err != nil {
		return fmt.Errorf("%w: already a contact or already pending", ErrBadRequest)
	}
	return nil
}
