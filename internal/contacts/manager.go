// Package contacts implements the contact lifecycle of SPEC §9 / PACT §5–§6:
// invite issuance and redemption, guest contact requests, the pending-tier answer
// tools, and the always-available contact-tier tools, including the card refresh
// a renewal or a move is followed by (update_contact).
package contacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Wire error codes (PACT §12).
var (
	ErrInviteInvalid    = errors.New("invite_invalid")
	ErrIdentityRequired = errors.New("identity_required")
	ErrUnknownContact   = errors.New("unknown_contact")
	ErrBadRequest       = errors.New("bad_request")
)

// MaxInviteTTL is PACT §12's cap on expires_at; exported so the limits the
// node advertises (get_card) come from the same authority that enforces them.
const MaxInviteTTL = 90 * 24 * time.Hour
const defaultInviteTTL = 14 * 24 * time.Hour

type Manager struct {
	Store store.Store
	Now   func() time.Time // injectable clock
	// OnRequest fires when a contact request lands awaiting the owner's
	// approval. It is how `pact://requests` and the portal's live view learn
	// there is something to look at (SPEC §8.5, §9.1); nothing produced that
	// event, so the resource an agent could subscribe to never fired.
	OnRequest func(accountID, contactFpr string)
}

func (m *Manager) notifyRequest(accountID, contactFpr string) {
	if m.OnRequest != nil {
		m.OnRequest(accountID, contactFpr)
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

/* ------------------------------- invites ------------------------------- */

type InviteOptions struct {
	TTL         time.Duration // 0 = default 14d; capped at 90d
	MaxUses     int64         // 0 = 1 (one-time); <0 = unlimited (stored as a large cap)
	AutoAccept  bool
	Preset      string
	Permissions []string
	Label       string
}

// CreateInvite mints the bearer token (returned exactly once) and stores its hash
// with the server-side settings (SPEC §9.2).
func (m *Manager) CreateInvite(ctx context.Context, accountID string, o InviteOptions) (token string, inv store.Invite, err error) {
	ttl := o.TTL
	if ttl == 0 {
		ttl = defaultInviteTTL
	}
	if ttl > MaxInviteTTL {
		return "", store.Invite{}, fmt.Errorf("%w: invite ttl exceeds 90 days", ErrBadRequest)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", store.Invite{}, err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	maxUses := o.MaxUses
	if maxUses == 0 {
		maxUses = 1
	}
	// The preset IS the grant: an invite carrying a preset but no explicit
	// permission list grants that preset's bundle, exactly as approving a
	// request with the same preset does (PACT §8).
	if len(o.Permissions) == 0 && o.Preset != "" {
		if perms, ok := LoadPresets(ctx, m.Store)[o.Preset]; ok {
			o.Permissions = append([]string(nil), perms...)
		}
	}
	if maxUses < 0 {
		maxUses = 1 << 30 // "public link": effectively unlimited, still countable
	}
	inv, err = m.Store.InsertInvite(ctx, store.Invite{
		AccountID: accountID, TokenHash: sum[:], ExpiresAt: m.now().Add(ttl).Unix(),
		MaxUses: maxUses, AutoAccept: o.AutoAccept, Preset: o.Preset,
		Permissions: o.Permissions, Label: o.Label,
	})
	return token, inv, err
}

// RedeemResult is what redeem_invite returns (PACT §6.2).
type RedeemResult struct {
	Status      string // accepted | pending
	Permissions []string
	// Silent: the caller is a root this account holds as other than a waiting request, and was
	// answered as a stranger with nothing written. The audit trail says so; the wire never does.
	Silent bool
}

// Proof is what a guest proved this call: a chain — the root that is the identity, the
// leaf's key, and the endpoint and leaf the pin records (PACT §14.2 rule 6, §14.3).
// SelfEndpoint is this account's own address, for the guard a guest's card must pass
// (PACT §3). A caller that proved no chain has the zero Proof, which is refused.
type Proof struct {
	Fingerprint  string // the root's: the identity
	SPKI         []byte // the leaf's key — what to seal to and verify under
	Endpoint     string
	Leaf         []byte
	SelfEndpoint string
	// RootCert is the root's DER when the proof came with a full chain. Empty
	// for a sealed call, where the chain is inside the ciphertext and only the
	// library's Decide sees it - such a pin gets its certificate the first time
	// the contact connects with a client certificate (migration 0029).
	RootCert []byte
}

// vet checks a guest's card against what the guest proved: the card must name the
// ROOT the chain proved, carry the leaf that chain presented, and name an endpoint
// the address guard allows — never loopback, link-local or private, never our own.
func (p Proof) vet(card string) (Card, error) {
	if p.Fingerprint == "" || len(p.SPKI) == 0 {
		return Card{}, fmt.Errorf("%w: needs a proven key", ErrIdentityRequired)
	}
	pc, err := ValidateInbound(card)
	if err != nil {
		return Card{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if pc.Key != p.Fingerprint {
		return Card{}, fmt.Errorf("%w: the card names another root than the chain proved", ErrIdentityRequired)
	}
	// Unconditional. These two sat inside `if p.Protocol == 2`, so a Proof without the flag —
	// a key and a fingerprint and nothing else — skipped both the binding of the card to the
	// proven leaf and the address guard. Nothing in production built one; nothing stopped it.
	if !bytes.Equal(pc.Cert, p.Leaf) {
		return Card{}, fmt.Errorf("%w: the card's certificate is not the proven leaf", ErrIdentityRequired)
	}
	if ok, why := pactidentity.AddressGuard(pc.Endpoint, p.SelfEndpoint, true); !ok {
		return Card{}, fmt.Errorf("%w: endpoint refused: %s", ErrBadRequest, why)
	}
	return pc, nil
}

func (p Proof) pin(c store.Contact) store.Contact {
	c.Fingerprint, c.SPKI = p.Fingerprint, p.SPKI
	c.Endpoint, c.Leaf = p.Endpoint, p.Leaf
	c.RootCert = p.RootCert
	return c
}

// RedeemAs performs the guest-tier redemption (SPEC §9.2): token by hash; expiry,
// revocation, and use-count enforced atomically; the caller's proven identity MUST
// be the root the submitted card's leaf names (guest binding, SPEC §5.3); what is
// pinned is that root, the endpoint, the leaf and the leaf's key.
//
// A use is spent only by a redemption that writes a row, in the same transaction as the write.
// A root this account already holds is decided BEFORE anything is spent:
//
//   - a request still waiting (pending_in) is that request redeeming a link: the row takes the
//     invite's status, grant and label, and one use is spent;
//   - any other row — blocked, or a pinned contact the node served at the guest tier because
//     the leaf that signed is older than the one it holds (PACT §14.3) — is answered exactly
//     what a stranger with the same link would be, and nothing is spent or written. PACT §12:
//     blocked MUST be indistinguishable from never-met. This used to spend the use, fail the
//     insert, and answer `invite_invalid`, which a stranger holding the same link is not told.
func (m *Manager) RedeemAs(ctx context.Context, accountID, token, card string, p Proof) (RedeemResult, error) {
	if _, err := p.vet(card); err != nil {
		return RedeemResult{}, err
	}
	callerFpr := p.Fingerprint
	sum := sha256.Sum256([]byte(token))
	inv, err := m.Store.GetInviteByHash(ctx, accountID, sum[:])
	if err != nil {
		return RedeemResult{}, fmt.Errorf("%w: unknown token", ErrInviteInvalid)
	}
	now := m.now().Unix()
	// What ConsumeInviteUse enforces, read without spending: a link a stranger would be refused
	// is refused to everyone, before a held row is looked at.
	if inv.RevokedAt != 0 || inv.ExpiresAt <= now || inv.Uses >= inv.MaxUses {
		return RedeemResult{}, fmt.Errorf("%w: expired, revoked, or used up", ErrInviteInvalid)
	}
	status := "pending_in"
	result := RedeemResult{Status: "pending"}
	if inv.AutoAccept {
		status = "active"
		result = RedeemResult{Status: "accepted", Permissions: inv.Permissions}
	}
	held, err := m.Store.GetContact(ctx, accountID, callerFpr)
	known := err == nil
	if known && held.Status != "pending_in" {
		result.Silent = true
		return result, nil
	}
	row := p.pin(store.Contact{
		AccountID: accountID, Status: status,
		Preset: inv.Preset, Permissions: inv.Permissions, DisplayName: CardName(card),
		Card: card, PinnedAt: now, InviteID: inv.ID,
	})
	err = m.Store.Atomically(ctx, func(tx store.Store) error {
		ok, err := tx.ConsumeInviteUse(ctx, inv.ID, now)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: expired, revoked, or used up", ErrInviteInvalid)
		}
		if known {
			wrote, err := tx.RedeemOverPendingContact(ctx, row)
			if err != nil {
				return err
			}
			if !wrote {
				// The owner decided on the request between the read above and this write.
				return fmt.Errorf("%w: that request was decided meanwhile", ErrInviteInvalid)
			}
			return nil
		}
		if _, err := tx.InsertContact(ctx, row); err != nil {
			// Another call inserted this root between the read above and this write.
			return fmt.Errorf("%w: already a contact or request pending", ErrInviteInvalid)
		}
		return nil
	})
	if err != nil {
		return RedeemResult{}, err
	}
	if status == "pending_in" {
		// An invite without auto-accept still needs the owner to look (§9.1).
		m.notifyRequest(accountID, callerFpr)
	}
	return result, nil
}

// RequestContact is the unsolicited guest path (PACT §6.2): lands pending_in for
// owner approval; same identity binding rule as redemption.
func (m *Manager) RequestContactAs(ctx context.Context, accountID, card, note string, p Proof) error {
	if _, err := p.vet(card); err != nil {
		return err
	}
	if len(note) > 1024 { // PACT §6.2: note ≤1 KiB
		return fmt.Errorf("%w: note over 1 KiB", ErrBadRequest)
	}
	_, err := m.Store.InsertContact(ctx, p.pin(store.Contact{
		AccountID: accountID, Status: "pending_in",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
	}))
	if err != nil {
		return fmt.Errorf("%w: already known", ErrBadRequest)
	}
	m.notifyRequest(accountID, p.Fingerprint)
	return nil
}

/* ---------------------------- pending tier ----------------------------- */

// ContactAccepted: the peer we invited (pending_out) confirms (PACT §6.2).
// ContactAccepted records a peer's approval: their post-approval card and the
// permissions they granted us (PACT §6.2). Both used to be discarded — the card
// was accepted and ignored, and the permission list was never even decoded — so
// an agent had no way to know what it may call on a contact except by probing.
func (m *Manager) ContactAccepted(ctx context.Context, accountID, callerFpr, card string, theirPermissions []string) error {
	c, err := m.Store.GetContact(ctx, accountID, callerFpr)
	if err != nil || c.Status != "pending_out" {
		return fmt.Errorf("%w: no pending invitation for this caller", ErrUnknownContact)
	}
	// The card must still be theirs: a peer cannot use its approval to hand us
	// somebody else's identity.
	if card != "" {
		pc, err := ValidateInbound(card)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
		// A card that is not the caller's own is a bad card, not a missing proof: the call
		// proved who it is; the card says otherwise. `bad_request` is what PACT §3 answers a
		// card at intake and §14.2 a card whose chain fails; `identity_required` means no
		// usable proof at all (§12), and the cloud answers this `bad_request` too.
		if pc.Key != callerFpr {
			return fmt.Errorf("%w: the card does not match the accepting identity", ErrBadRequest)
		}
	}
	if card == "" {
		card = c.Card
	}
	return m.Store.SetContactAccepted(ctx, accountID, callerFpr, card, theirPermissions, m.now().Unix())
}

// ContactRejected: the peer declines our approach. The pending_out row is demoted to blocked,
// not deleted (PACT §5.1: declining is a demotion): it is this side's record that the approach
// was declined, and an unblock forgets it (it was never active), after which we may ask again.
func (m *Manager) ContactRejected(ctx context.Context, accountID, callerFpr string) error {
	c, err := m.Store.GetContact(ctx, accountID, callerFpr)
	if err != nil || c.Status != "pending_out" {
		return fmt.Errorf("%w: no pending invitation for this caller", ErrUnknownContact)
	}
	return m.Store.UpdateContactStatus(ctx, accountID, callerFpr, "blocked")
}

/* -------------------------- always-available --------------------------- */

// UpdateContact refreshes a contact's card (PACT §6.2). The pin already followed
// the chain that carried this call (§5.3, §14.3 — decided before dispatch) and the
// root never moves, so what this writes is the card: it must be the root's own and
// must carry the leaf the pin now holds.
//
// It used to be "verified key rotation": a new card's fingerprint signed by the old
// pinned key. That was 1.x, where the identity WAS a key and so a key change had to
// be provable. A root does not change, so there is nothing left to prove here.
func (m *Manager) UpdateContact(ctx context.Context, accountID, oldFpr, newCard string) error {
	c, err := m.Store.GetContact(ctx, accountID, oldFpr)
	if err != nil {
		return fmt.Errorf("%w: caller is not a contact", ErrUnknownContact)
	}
	nc, err := ValidateInbound(newCard)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	// Both refusals are `bad_request`, as ContactAccepted's is: the call's chain proved the
	// caller, and the card disagrees with that proof (PACT §3, §14.2). One fault, one code on
	// every implementation — the cloud's update_contact answers the same.
	if nc.Key != oldFpr {
		return fmt.Errorf("%w: the card names another root", ErrBadRequest)
	}
	if len(c.Leaf) > 0 && !bytes.Equal(nc.Cert, c.Leaf) {
		return fmt.Errorf("%w: the card's certificate is not the leaf this call proved", ErrBadRequest)
	}
	// The NAME the owner approved stays put. `update_contact` is available at
	// contact tier regardless of permissions and replaces the stored card, which
	// carries FN — so passing the new card's FN here would let a contact accepted
	// as "Alina" rename itself to "Bharat" afterwards, and the owner's decision to
	// trust the name they approved would be worth nothing. A refresh the owner asked
	// for (`refresh_contact`, the button on the contact's page) may move the name,
	// because there we fetched the card ourselves; a card the peer pushed may not.
	return m.Store.UpdateContactCard(ctx, accountID, oldFpr, newCard, c.DisplayName)
}

// RemoveContact deletes the pin (PACT §6.2); enforcement is local by design.
func (m *Manager) RemoveContact(ctx context.Context, accountID, callerFpr string) error {
	c, err := m.Store.GetContact(ctx, accountID, callerFpr)
	if err != nil {
		return fmt.Errorf("%w", ErrUnknownContact)
	}
	// PACT §5.3 "after a removal": a 2.0 root that removed us and returns with a
	// newer leaf inside 30 days is asked about, whatever the setting says — a
	// host being left could otherwise erase the person's contacts on its way out.
	if len(c.Leaf) > 0 {
		if err := m.Store.UpsertTombstone(ctx, store.Tombstone{AccountID: accountID, Root: callerFpr, Leaf: c.Leaf, At: m.now().Unix()}); err != nil {
			return err
		}
	}
	// Status flip to blocked would be silent demotion; removal is the peer-visible
	// path — the row goes away entirely so re-adding starts fresh (SPEC §9.1:
	// `active --> none`, "unpins that caller").
	return m.Store.DeleteContact(ctx, accountID, callerFpr)
}

// DecideAddress is the owner's answer to a contact waiting at a new address
// under `accept_new_hosts = ask` (PACT §5.3): approving re-pins as `auto` would
// have — the endpoint, the leaf and its key move, the old endpoint is
// remembered for the address-claim rule, and any removal tombstone is spent;
// rejecting leaves the pin as it was.
func (m *Manager) DecideAddress(ctx context.Context, accountID, root string, approve bool) (store.PendingAddress, error) {
	p, err := m.Store.GetPendingAddress(ctx, accountID, root)
	if err != nil {
		return store.PendingAddress{}, fmt.Errorf("%w: no address is pending for %s", ErrUnknownContact, root)
	}
	if !approve {
		return p, m.Store.DeletePendingAddress(ctx, accountID, root)
	}
	leaf, err := pactidentity.Parse(p.Leaf)
	if err != nil {
		return p, fmt.Errorf("%w: pending leaf unreadable", ErrBadRequest)
	}
	now := m.now().Unix()
	c, err := m.Store.GetContact(ctx, accountID, root)
	if err != nil {
		// A root that returned after a removal has no pin: it is re-added as an
		// active contact at the address it asked from, the way approving a
		// request would, with its former permissions gone.
		_, err = m.Store.InsertContact(ctx, store.Contact{AccountID: accountID, Fingerprint: root, SPKI: leaf.SPKI, Status: "active",
			Endpoint: p.Endpoint, Leaf: p.Leaf, PinnedAt: now, DisplayName: leaf.Subject, RootCert: p.RootCert})
		if err != nil {
			return p, err
		}
	} else {
		if c.Endpoint != "" && c.Endpoint != p.Endpoint {
			if err := m.Store.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: accountID, Root: root, Endpoint: c.Endpoint, At: now}); err != nil {
				return p, err
			}
		}
		if err := m.Store.RepinContactAddress(ctx, accountID, root, p.Endpoint, p.Leaf, leaf.SPKI, now); err != nil {
			return p, err
		}
	}
	_ = m.Store.DeleteTombstone(ctx, accountID, root)
	return p, m.Store.DeletePendingAddress(ctx, accountID, root)
}

/* ----------------------------- card helpers ---------------------------- */

// CardName extracts FN for display; "" on any parse failure.
func CardName(card string) string {
	c, err := ParseCard(card)
	if err != nil {
		return ""
	}
	return c.FN
}

var _ = identity.Fingerprint // referenced by tests; keeps the import honest
