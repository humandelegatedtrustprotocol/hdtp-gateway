// Package contacts implements the contact lifecycle of SPEC §9 / PACT §5–§6:
// invite issuance and redemption, guest contact requests, the pending-tier answer
// tools, and the always-available contact-tier tools including verified key
// rotation (update_contact).
package contacts

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
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
}

// Redeem performs the guest-tier redemption (SPEC §9.2): token by hash; expiry,
// revocation, and use-count enforced atomically; the caller's proven identity MUST
// equal the submitted card's X-PACT-KEY (guest binding, SPEC §5.3); the proven SPKI
// is pinned in full.
func (m *Manager) Redeem(ctx context.Context, accountID, token, card, callerFpr string, callerSPKI []byte) (RedeemResult, error) {
	if callerFpr == "" || len(callerSPKI) == 0 {
		return RedeemResult{}, fmt.Errorf("%w: redemption needs a proven key", ErrIdentityRequired)
	}
	pc, err := ValidateInbound(card)
	if err != nil {
		return RedeemResult{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if pc.Key != callerFpr {
		return RedeemResult{}, fmt.Errorf("%w: proven key does not match the card's X-PACT-KEY", ErrIdentityRequired)
	}
	sum := sha256.Sum256([]byte(token))
	inv, err := m.Store.GetInviteByHash(ctx, accountID, sum[:])
	if err != nil {
		return RedeemResult{}, fmt.Errorf("%w: unknown token", ErrInviteInvalid)
	}
	ok, err := m.Store.ConsumeInviteUse(ctx, inv.ID, m.now().Unix())
	if err != nil {
		return RedeemResult{}, err
	}
	if !ok {
		return RedeemResult{}, fmt.Errorf("%w: expired, revoked, or used up", ErrInviteInvalid)
	}
	status := "pending_in"
	result := RedeemResult{Status: "pending"}
	if inv.AutoAccept {
		status = "active"
		result = RedeemResult{Status: "accepted", Permissions: inv.Permissions}
	}
	_, err = m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: callerFpr, SPKI: callerSPKI, Status: status,
		Preset: inv.Preset, Permissions: inv.Permissions, DisplayName: CardName(card),
		Card: card, PinnedAt: m.now().Unix(), InviteID: inv.ID,
	})
	if err != nil {
		return RedeemResult{}, fmt.Errorf("%w: already a contact or request pending", ErrInviteInvalid)
	}
	if status == "pending_in" {
		// An invite without auto-accept still needs the owner to look (§9.1).
		m.notifyRequest(accountID, callerFpr)
	}
	return result, nil
}

// RequestContact is the unsolicited guest path (PACT §6.2): lands pending_in for
// owner approval; same identity binding rule as redemption.
func (m *Manager) RequestContact(ctx context.Context, accountID, card, note, callerFpr string, callerSPKI []byte) error {
	if callerFpr == "" || len(callerSPKI) == 0 {
		return fmt.Errorf("%w: request needs a proven key", ErrIdentityRequired)
	}
	pc, err := ValidateInbound(card)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if pc.Key != callerFpr {
		return fmt.Errorf("%w: proven key does not match the card's X-PACT-KEY", ErrIdentityRequired)
	}
	if len(note) > 1024 { // PACT §6.2: note ≤1 KiB
		return fmt.Errorf("%w: note over 1 KiB", ErrBadRequest)
	}
	_, err = m.Store.InsertContact(ctx, store.Contact{
		AccountID: accountID, Fingerprint: callerFpr, SPKI: callerSPKI, Status: "pending_in",
		DisplayName: CardName(card), Card: card, PinnedAt: m.now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("%w: already known", ErrBadRequest)
	}
	m.notifyRequest(accountID, callerFpr)
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
		if pc.Key != callerFpr {
			return fmt.Errorf("%w: the card does not match the accepting identity", ErrIdentityRequired)
		}
	}
	if card == "" {
		card = c.Card
	}
	return m.Store.SetContactAccepted(ctx, accountID, callerFpr, card, theirPermissions, m.now().Unix())
}

// ContactRejected: the peer declines; the pending row is removed silently.
func (m *Manager) ContactRejected(ctx context.Context, accountID, callerFpr string) error {
	c, err := m.Store.GetContact(ctx, accountID, callerFpr)
	if err != nil || c.Status != "pending_out" {
		return fmt.Errorf("%w: no pending invitation for this caller", ErrUnknownContact)
	}
	return m.Store.UpdateContactStatus(ctx, accountID, callerFpr, "blocked")
}

/* -------------------------- always-available --------------------------- */

// UpdateContact performs verified key rotation (PACT §2): the NEW card's
// fingerprint, signed by the OLD pinned key, re-pins the contact. The new SPKI is
// the caller's presently proven key and MUST hash to the new card's X-PACT-KEY.
func (m *Manager) UpdateContact(ctx context.Context, accountID, oldFpr, newCard string, sig []byte, provenNewSPKI []byte) error {
	c, err := m.Store.GetContact(ctx, accountID, oldFpr)
	if err != nil {
		return fmt.Errorf("%w: caller is not a contact", ErrUnknownContact)
	}
	nc, err := ValidateInbound(newCard)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	newFpr := nc.Key
	// PACT §6.2: the rotating peer calls as its OLD identity — that is what the
	// pin recognizes — and the new key is proven by the card plus the old-key
	// signature below.
	//
	// Which key the transport presents is therefore NOT a free choice, and this
	// used to demand the wrong one. SPEC §3.9 step 4 is explicit that during the
	// grace period "outbound calls to a contact that has not yet re-pinned
	// present the OLD certificate", which is exactly what `account rotate`
	// builds. Requiring the presented key to hash to the NEW card rejected every
	// real rotation and turned rotation into contact loss.
	//
	// So there are two honest cases and one lie:
	//   - the OLD key (the grace-period path): expected, proves no new key;
	//   - the NEW key (a peer that already reconnected with it): proves it;
	//   - anything else: a third key vouching for a card it does not own.
	proven := provenNewSPKI
	if len(proven) > 0 {
		switch fingerprintOf(proven) {
		case newFpr:
			// the new key proved itself
		case oldFpr:
			proven = nil // the pinned identity, as §3.9 step 4 requires
		default:
			return fmt.Errorf("%w: presented key is neither the pinned identity "+
				"nor the new card's", ErrIdentityRequired)
		}
	}
	// Old-key endorsement: signature over the new fingerprint string (PACT §2).
	//
	// The verifying key is the PINNED one. Usually we hold its SPKI outright.
	// After a rotation that proved no key we hold only the fingerprint (E7
	// option B), and then the caller's presented certificate supplies the bytes
	// — admissible because it is bound to the pin by hash, the same rule §4 uses
	// for a sealed sender we have not pinned. A key that does not hash to the
	// pin is not the pinned key, and never verifies anything.
	verifySPKI := c.SPKI
	if len(verifySPKI) == 0 && len(provenNewSPKI) > 0 && fingerprintOf(provenNewSPKI) == oldFpr {
		verifySPKI = provenNewSPKI
	}
	if len(verifySPKI) == 0 {
		return fmt.Errorf("%w: no pinned key to verify this rotation against — "+
			"reconnect with the pinned identity first", ErrIdentityRequired)
	}
	oldPub, err := x509.ParsePKIXPublicKey(verifySPKI)
	if err != nil {
		return fmt.Errorf("%w: pinned key unreadable", ErrBadRequest)
	}
	msg := []byte(newFpr)
	switch pk := oldPub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(pk, h[:], sig) {
			return fmt.Errorf("%w: rotation signature invalid", ErrIdentityRequired)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, msg, sig) {
			return fmt.Errorf("%w: rotation signature invalid", ErrIdentityRequired)
		}
	default:
		return fmt.Errorf("%w: pinned key type unsupported", ErrBadRequest)
	}
	// An endpoint change re-sends the SAME identity. If this call proved no key
	// — the peer reached us sealed-as-pinned, or through a path that carries no
	// certificate — writing an empty SPKI would throw away a key we already
	// hold and could no longer seal to them. A key CHANGE is different: keeping
	// the old SPKI there would pin a key §3.9 step 5 destroys at grace expiry,
	// leaving us sealing into a key the peer no longer holds. So a changed
	// fingerprint drops to fingerprint-only until the new key connects and
	// BindSPKI records it (escalation E7, option B).
	spki := proven
	if len(spki) == 0 && newFpr == oldFpr {
		spki = c.SPKI
	}
	return m.Store.RepinContact(ctx, accountID, oldFpr, newFpr, spki, newCard, m.now().Unix())
}

// fingerprintOf is PACT §2's identity for a DER SPKI.
func fingerprintOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// BindSPKI records a re-pinned contact's full public key the first time the
// new key connects: the presented SPKI MUST hash to the pinned fingerprint.
func (m *Manager) BindSPKI(ctx context.Context, accountID, fpr string, spki []byte) error {
	if fingerprintOf(spki) != fpr {
		return fmt.Errorf("%w: key does not match the pinned fingerprint", ErrIdentityRequired)
	}
	c, err := m.Store.GetContact(ctx, accountID, fpr)
	if err != nil {
		return fmt.Errorf("%w", ErrUnknownContact)
	}
	if len(c.SPKI) > 0 {
		return nil // already bound
	}
	return m.Store.RepinContact(ctx, accountID, fpr, fpr, spki, c.Card, m.now().Unix())
}

// RemoveContact deletes the pin (PACT §6.2); enforcement is local by design.
func (m *Manager) RemoveContact(ctx context.Context, accountID, callerFpr string) error {
	if _, err := m.Store.GetContact(ctx, accountID, callerFpr); err != nil {
		return fmt.Errorf("%w", ErrUnknownContact)
	}
	// Status flip to blocked would be silent demotion; removal is the peer-visible
	// path — the row goes away entirely so re-adding starts fresh (SPEC §9.1:
	// `active --> none`, "unpins that caller").
	return m.Store.DeleteContact(ctx, accountID, callerFpr)
}

/* ----------------------------- card helpers ---------------------------- */

// CardKey extracts X-PACT-KEY via the real parser; "" on any parse failure.
func CardKey(card string) string {
	c, err := ParseCard(card)
	if err != nil {
		return ""
	}
	return c.Key
}

// CardName extracts FN for display; "" on any parse failure.
func CardName(card string) string {
	c, err := ParseCard(card)
	if err != nil {
		return ""
	}
	return c.FN
}

var _ = identity.Fingerprint // referenced by tests; keeps the import honest
