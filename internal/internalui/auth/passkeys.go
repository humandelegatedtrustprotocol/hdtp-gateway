// Package auth implements owner authentication (SPEC §3.1, §8.3): WebAuthn
// passkeys — multiple per owner, each with an owner-supplied tag, managed from
// portal, owner MCP, and CLI — plus cookie sessions. Registration is gated the
// same way as the setup wizard: first passkey via loopback/one-time token; later
// passkeys require a logged-in owner session.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

const sessionTTL = 12 * time.Hour

// RelyingParty is the (RP ID, origin) pair a ceremony runs under. It cannot be
// fixed when the service is built: a browser derives the credential's RP ID hash
// from the origin it is on, so a portal reachable at `localhost` and one at a
// domain are different relying parties. Both halves of a ceremony must use the
// SAME pair, which is why it is stashed with the challenge.
//
// A consequence worth telling owners rather than letting them discover: a
// passkey registered against `localhost` will not work once the portal moves to
// a domain. That is WebAuthn, not a defect; `passkey reset-wizard` is the way back.
type RelyingParty struct {
	ID     string // e.g. "localhost" or "pact.example.com"
	Origin string // e.g. "http://localhost:8080" or "https://pact.example.com"
}

// ceremony is an in-flight challenge together with the relying party it was
// issued for.
type ceremony struct {
	data *webauthn.SessionData
	wa   *webauthn.WebAuthn
	// handle is the WebAuthn user id this ceremony offered the authenticator.
	// The authenticator stores it with the credential and replays it on every
	// later login, so the owner created at the end MUST carry it as its id.
	handle string
}

type Service struct {
	Store store.Store
	Now   func() time.Time

	mu      sync.Mutex
	pending map[string]ceremony // ceremony id -> in-flight challenge + its RP

	// firstMu serializes the creation of the FIRST owner. "The first passkey
	// decides who owns this node" is the trust root, and the caller's gate reads
	// a count in one request while the insert happens in another — so without a
	// critical section here two concurrent finishes both pass it.
	firstMu sync.Mutex
}

// New builds the service. The relying party arrives per ceremony.
func New(st store.Store) *Service {
	return &Service{Store: st, pending: map[string]ceremony{}}
}

// ValidRelyingPartyID reports why a hostname cannot be a passkey relying party, in the LIBRARY'S own
// judgement and as the origin policy will present it (lowercased) — so a config refused by this is
// exactly a config whose ceremonies `webauthnFor` would have refused, and no other.
func ValidRelyingPartyID(host string) error {
	return protocol.ValidateRPID(strings.ToLower(host))
}

// webauthnFor builds the RP-specific verifier. RP ID must be a registrable
// suffix of the origin's host, which is exactly the rule that made the previous
// fixed pairing (`localhost` with a `127.0.0.1` origin) unusable.
func webauthnFor(rp RelyingParty) (*webauthn.WebAuthn, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "pact-gateway",
		RPID:          rp.ID,
		RPOrigins:     []string{rp.Origin},
		// Login is discoverable (BeginLogin offers no credential list), so a passkey is useful only
		// if the authenticator can find it by itself. Left unset, the browser's default is
		// residentKey "discouraged", and an authenticator that honours it registers a credential
		// the sign-in page can never offer.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: relying party %s/%s: %w", rp.ID, rp.Origin, err)
	}
	return wa, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

/* ------------------------------ webauthn user ------------------------------ */

// ownerUser adapts an owner + passkeys to webauthn.User.
type ownerUser struct {
	owner store.Owner
	creds []webauthn.Credential
}

func (u ownerUser) WebAuthnID() []byte                         { return []byte(u.owner.ID) }
func (u ownerUser) WebAuthnName() string                       { return u.owner.DisplayName }
func (u ownerUser) WebAuthnDisplayName() string                { return u.owner.DisplayName }
func (u ownerUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// storedCred is what credentials.data holds for kind=passkey.
type storedCred struct {
	Cred webauthn.Credential `json:"cred"`
}

func (s *Service) passkeysFor(ctx context.Context, ownerID string) ([]webauthn.Credential, error) {
	all, err := s.Store.ListCredentialsByKind(ctx, "passkey")
	if err != nil {
		return nil, err
	}
	var out []webauthn.Credential
	for _, c := range all {
		if ownerID != "" && c.OwnerID != ownerID {
			continue
		}
		var sc storedCred
		// A row that will not decode is an ERROR, not a row to step over. Skipping it made
		// `CountCredentialsByKind` and this list disagree about the same table: the count
		// still saw the row, so `needs_setup` stayed false and the portal would not offer
		// the wizard, while `BeginLogin` saw an empty list and said "no passkeys
		// registered". Somebody whose only passkey row had been corrupted was told nothing
		// was registered, could not reach the enrolment that fixes it, and the node
		// recorded no reason anywhere. Saying which credential will not read turns a
		// lockout with no diagnostic into one line an operator can act on.
		//
		// It is not a permission bug: the §8.3 setup window is decided by the COUNT
		// (internal/internalui/server.go), which a corrupt row satisfies, so this never
		// opened the wizard to anybody.
		if err := json.Unmarshal(c.Data, &sc); err != nil {
			return nil, fmt.Errorf("auth: stored passkey %s will not decode: %w", c.ID, err)
		}
		out = append(out, sc.Cred)
	}
	return out, nil
}

/* ------------------------------- ceremonies ------------------------------- */

func (s *Service) stash(c ceremony) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id] = c
	return id
}

func (s *Service) take(id string) (ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pending[id]
	delete(s.pending, id)
	return c, ok
}

// BeginRegistration starts a passkey ceremony for ownerID; ownerName is used to
// create the owner on FIRST registration (ownerID "" = new owner).
func (s *Service) BeginRegistration(ctx context.Context, rp RelyingParty, ownerID, ownerName string) (options any, ceremonyID string, err error) {
	wa, err := webauthnFor(rp)
	if err != nil {
		return nil, "", err
	}
	// The user handle is decided HERE, because this is the moment the
	// authenticator records it — permanently, for this credential. It used to be
	// the literal string "pending" when no owner existed yet, and
	// FinishRegistration then rewrote the server's own copy to the real owner id
	// so the attestation verified. That made registration succeed and login
	// impossible: a browser replays "pending", the node looks for an owner by
	// that name, finds none, and refuses a passkey it just issued.
	var owner store.Owner
	if ownerID == "" {
		// A first passkey mints the id the owner will be created under. If an
		// owner already exists, this ceremony joins them and uses theirs — which
		// is also what makes `passkey reset-wizard` add a second usable key.
		owners, lerr := s.Store.ListOwners(ctx)
		if lerr != nil {
			return nil, "", lerr
		}
		if len(owners) > 0 {
			owner = owners[0]
		} else {
			owner = store.Owner{ID: newHandle(), DisplayName: ownerName}
		}
	} else {
		owner, err = s.Store.GetOwner(ctx, ownerID)
		if err != nil {
			return nil, "", err
		}
	}
	creds, err := s.passkeysFor(ctx, ownerID)
	if err != nil {
		return nil, "", err
	}
	opts, sd, err := wa.BeginRegistration(ownerUser{owner: owner, creds: creds})
	if err != nil {
		return nil, "", fmt.Errorf("auth: %w", err)
	}
	return opts, s.stash(ceremony{data: sd, wa: wa, handle: owner.ID}), nil
}

// FinishRegistration verifies the attestation and stores the tagged passkey,
// creating the owner when this is the very first one.
func (s *Service) FinishRegistration(ctx context.Context, ceremonyID, ownerID, ownerName, tag string, r *http.Request) (string, error) {
	c, ok := s.take(ceremonyID)
	if !ok {
		return "", errors.New("auth: unknown or reused ceremony")
	}
	sd := c.data
	if ownerID == "" {
		s.firstMu.Lock()
		// Re-check INSIDE the lock: whoever got here first has already created
		// the owner, and this ceremony joins them rather than creating a second.
		owners, err := s.Store.ListOwners(ctx)
		if err != nil {
			s.firstMu.Unlock()
			return "", err
		}
		if len(owners) > 0 {
			ownerID = owners[0].ID
			s.firstMu.Unlock()
			// The credential the authenticator just made is bound to the handle
			// this ceremony offered. If an owner appeared under a DIFFERENT id
			// since then — a concurrent first registration — that credential can
			// never log in, so refuse it rather than store a key that looks fine
			// and is not. Starting the ceremony again picks up the owner that
			// now exists.
			if c.handle != "" && ownerID != c.handle {
				return "", errors.New("auth: another registration completed first; start again")
			}
		} else {
			// Created under the handle the authenticator already recorded, so
			// the two agree for the life of the credential.
			o, cerr := s.Store.CreateOwnerWithID(ctx, c.handle, ownerName)
			s.firstMu.Unlock()
			if cerr != nil {
				return "", cerr
			}
			ownerID = o.ID
			// SPEC §3.3: account-scoped actions require membership. Accounts
			// provisioned before the first passkey — the order the README
			// quickstart actually produces — would otherwise stay invisible to
			// every owner surface (P14-05c).
			if aerr := identity.AdoptOrphanAccounts(ctx, s.Store, ownerID); aerr != nil {
				return "", aerr
			}
		}
	}
	owner, err := s.Store.GetOwner(ctx, ownerID)
	if err != nil {
		return "", err
	}
	cred, err := c.wa.FinishRegistration(ownerUser{owner: owner}, *sd, r)
	if err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	raw, err := json.Marshal(storedCred{Cred: *cred})
	if err != nil {
		return "", err
	}
	if tag == "" {
		tag = "passkey"
	}
	if err := s.Store.InsertCredential(ctx, store.Credential{
		OwnerID: ownerID, Kind: "passkey", Tag: tag, Data: raw,
	}); err != nil {
		return "", err
	}
	return ownerID, nil
}

// BeginLogin starts an assertion ceremony over ALL registered passkeys (the
// owner is identified at finish by which credential signed).
func (s *Service) BeginLogin(ctx context.Context, rp RelyingParty) (options any, ceremonyID string, err error) {
	wa, err := webauthnFor(rp)
	if err != nil {
		return nil, "", err
	}
	creds, err := s.passkeysFor(ctx, "")
	if err != nil {
		return nil, "", err
	}
	if len(creds) == 0 {
		return nil, "", errors.New("auth: no passkeys registered")
	}
	opts, sd, err := wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("auth: %w", err)
	}
	return opts, s.stash(ceremony{data: sd, wa: wa}), nil
}

// FinishLogin verifies the assertion and returns a session token.
func (s *Service) FinishLogin(ctx context.Context, ceremonyID string, r *http.Request) (string, error) {
	c, ok := s.take(ceremonyID)
	if !ok {
		return "", errors.New("auth: unknown or reused ceremony")
	}
	sd := c.data
	var matchedOwner string
	_, err := c.wa.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		ownerID := string(userHandle)
		owner, err := s.Store.GetOwner(ctx, ownerID)
		if err != nil {
			return nil, err
		}
		creds, err := s.passkeysFor(ctx, ownerID)
		if err != nil {
			return nil, err
		}
		matchedOwner = ownerID
		return ownerUser{owner: owner, creds: creds}, nil
	}, *sd, r)
	if err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	return s.mintSession(ctx, matchedOwner)
}

/* -------------------------------- sessions -------------------------------- */

// MintSession issues a portal session for an owner who has just proven
// possession of a credential. Registration is such a proof — the ceremony is
// signed by the authenticator, bound to this origin — so the portal signs the
// owner in at the end of setup rather than demanding the same authenticator
// again one second later, which reads as the registration having failed.
func (s *Service) MintSession(ctx context.Context, ownerID string) (string, error) {
	return s.mintSession(ctx, ownerID)
}

func (s *Service) mintSession(ctx context.Context, ownerID string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	now := s.now()
	if err := s.Store.InsertSession(ctx, tok, ownerID, now.Unix(), now.Add(sessionTTL).Unix()); err != nil {
		return "", err
	}
	return tok, nil
}

// SessionOwner validates a session token; "" when invalid or expired.
func (s *Service) SessionOwner(ctx context.Context, token string) string {
	if token == "" {
		return ""
	}
	ownerID, exp, err := s.Store.GetSession(ctx, token)
	if err != nil || s.now().Unix() >= exp {
		return ""
	}
	return ownerID
}

func (s *Service) Logout(ctx context.Context, token string) {
	_ = s.Store.RemoveSession(ctx, token)
}

/* ------------------------------- management ------------------------------- */

type PasskeyInfo struct {
	ID        string `json:"id"`
	OwnerID   string `json:"owner_id"`
	Tag       string `json:"tag"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Service) ListPasskeys(ctx context.Context) ([]PasskeyInfo, error) {
	all, err := s.Store.ListCredentialsByKind(ctx, "passkey")
	if err != nil {
		return nil, err
	}
	out := make([]PasskeyInfo, 0, len(all))
	for _, c := range all {
		out = append(out, PasskeyInfo{ID: c.ID, OwnerID: c.OwnerID, Tag: c.Tag, CreatedAt: c.CreatedAt})
	}
	return out, nil
}

// ErrLastPasskey says the removal was refused because it would leave the node
// with none. Removing the last one locks the owner out of the portal, and zero
// passkeys re-opens the setup wizard (§8.3) — so the node would become claimable
// by whoever reaches it first.
var ErrLastPasskey = errors.New("auth: that is the only passkey registered")

// ErrNoSuchPasskey says the id did not name a registered passkey.
var ErrNoSuchPasskey = errors.New("auth: no such passkey")

// RemovePasskey deletes a passkey unless it is the last one.
//
// The invariant lives HERE, not in the callers. The portal and the owner MCP
// each used to read the list, decide, and then delete — so two removals racing
// on the final two passkeys could both see "there are two" and both delete,
// leaving zero. The store performs the count and the delete as one statement,
// which is what makes the check binding rather than advisory.
func (s *Service) RemovePasskey(ctx context.Context, id string) error {
	removed, err := s.Store.RemoveCredentialIfNotLast(ctx, id, "passkey")
	if err != nil {
		return err
	}
	if !removed {
		// Either it was the last passkey, or there was no such id. Distinguish
		// them, so a caller does not report a lockout that did not happen.
		list, lerr := s.ListPasskeys(ctx)
		if lerr != nil {
			return lerr
		}
		for _, pk := range list {
			if pk.ID == id {
				return ErrLastPasskey
			}
		}
		return ErrNoSuchPasskey
	}
	return nil
}

// newHandle mints the id a first owner will be created under. It is generated
// before any store row exists because the authenticator must be handed it at
// BeginRegistration — the handle and the owner id are the same value, and they
// have to be, because WebAuthn replays the handle on every login.
func newHandle() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // a node that cannot read entropy must not mint identities
	}
	return hex.EncodeToString(b)
}
