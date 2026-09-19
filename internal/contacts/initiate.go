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
	"bytes"
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// Initiated records a contact the owner started: we called the peer's
// `redeem_invite` or `request_contact`, and this is what we keep locally.
//
// `accepted` is the peer's own answer — an invite with auto-accept returns
// `accepted` and grants permissions immediately, so there is nothing to wait
// for; anything else lands `pending_out` until they approve, at which point
// their `answer_request` reaches ContactAccepted.
//
// The identity check is not ceremony. The pin IS the identity (PACT §2), so
// recording a contact whose pinned ROOT is not the root its card's certificate
// names would let a tampered invite bind us to an attacker under the peer's name,
// and every later chain check would then pass for the wrong party.
//
// `spki` is the LEAF key the peer proved on this exchange, not the identity: in
// 1.x the two were the same value and this checked that they hashed to each other.
// A leaf key changes at every renewal, so what is checked now is the root.
func (m *Manager) Initiated(ctx context.Context, accountID, peerFpr, card string,
	spki []byte, accepted bool, permissions []string) error {

	if peerFpr == "" || len(spki) == 0 {
		return fmt.Errorf("%w: a contact needs a proven key", ErrIdentityRequired)
	}
	c, err := ValidateInbound(card)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if c.Key != peerFpr {
		return fmt.Errorf("%w: the card's certificate does not name the identity being pinned", ErrIdentityRequired)
	}
	// And the key proved on this exchange must be the one the card's leaf carries.
	// In 1.x this read "the key hashes to the fingerprint being pinned", because
	// the pin and the key were one value; the pin is the root now, so the leaf is
	// what the card is checked against.
	leaf, perr := pactidentity.Parse(c.Cert)
	if perr != nil || !bytes.Equal(leaf.SPKI, spki) {
		return fmt.Errorf("%w: the proven key is not the one this card's certificate carries", ErrIdentityRequired)
	}
	// Always inserted pending_out, then moved on by the SAME transition a peer's
	// later approval takes. Reusing it rather than writing "active" directly is
	// deliberate: that path already validates the card against the identity and
	// already knows where the peer's grant belongs.
	if _, err := m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: peerFpr, SPKI: spki, Status: "pending_out",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
		Endpoint: c.Endpoint, Leaf: c.Cert,
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

// InitiatedByFingerprint is Initiated for the `request_contact` path, where we hold the peer's
// card and pin the root it names, the address its leaf names, the leaf, and the leaf's KEY.
//
// The key was left out, on the reasoning that it "arrives with the first chain that validates".
// That was true when a card carried only a key's hash. A 2.0 card carries the leaf certificate,
// and the key is in it — this function already stored that leaf. Storing the leaf without its key
// left a contact that, once the peer accepted, was active with no key to seal to: every later
// call went PLAINTEXT to a `seal: optional` peer and failed outright to a `required` one
// ("only their fingerprint is pinned"), while the key sat inside the certificate on file.
// Nothing fills it in later either: `contact_accepted` writes the card and the grant, and a
// chain presenting the SAME leaf is the pinned leaf, so it re-pins nothing (PACT §14.3).
func (m *Manager) InitiatedByFingerprint(ctx context.Context, accountID, peerFpr, card string) error {
	if peerFpr == "" {
		return fmt.Errorf("%w: a contact needs a fingerprint", ErrIdentityRequired)
	}
	c, err := ValidateInbound(card)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if c.Key != peerFpr {
		return fmt.Errorf("%w: the card's certificate does not name the identity being pinned", ErrIdentityRequired)
	}
	leaf, err := pactidentity.Parse(c.Cert)
	if err != nil {
		return fmt.Errorf("%w: the card's certificate does not parse: %v", ErrBadRequest, err)
	}
	if _, err := m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: peerFpr, SPKI: leaf.SPKI, Status: "pending_out",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
		Endpoint: c.Endpoint, Leaf: c.Cert,
	}); err != nil {
		return fmt.Errorf("%w: already a contact or already pending", ErrBadRequest)
	}
	return nil
}
