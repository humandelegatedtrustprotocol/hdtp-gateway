package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// signBytes signs with the encodings PACT §13.1 pins per algorithm: ECDSA over SHA-256 as ASN.1
// DER, Ed25519 per RFC 8032. It is the counterpart of VerifyBytes.
//
// It had an exported twin, `SignBytes`, "what produces the old-key endorsement a peer checks in
// `update_contact`" — 1.x key rotation, where a successor key had to be signed by its predecessor.
// Nothing endorses a key now; two tests were its last callers, and they sign with the library, as
// the peer they are playing would.
func signBytes(kp *Keypair, msg []byte) ([]byte, error) {
	switch k := kp.Signer.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(msg)
		return ecdsa.SignASN1(rand.Reader, k, sum[:])
	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg), nil
	default:
		return nil, fmt.Errorf("identity: unsupported signer %T", kp.Signer)
	}
}

// keyAAD binds sealed private keys to their column (SPEC §3.7, keyring AAD rule).
const keyAAD = "accounts.key_sealed"

// Manager creates and loads account identities: keypair generation, fingerprinting,
// and private-key sealing through the node keyring.
type Manager struct {
	Store   store.Store
	Keyring *core.Keyring
}

// CreateAccount makes the account row, generates its keypair, and binds the
// fingerprint + sealed key in one flow (SPEC §3.2).
func (m *Manager) CreateAccount(ctx context.Context, slug, displayName string, algo Algo) (store.Account, error) {
	// The display name is written into this account's card as one line (PACT §3). A control character
	// in it is a card the writer refuses to write — a line break used to put a property of the NAME'S
	// choosing into the card this node serves — so the account is refused here, before a key is made
	// for it, and not at the first request for a card it cannot have.
	for _, r := range displayName {
		if unicode.IsControl(r) {
			return store.Account{}, errors.New("identity: a display name carries no control character (it is one line of the account's card)")
		}
	}
	if algo == "" {
		algo = AlgoP256
	}
	kp, err := Generate(algo)
	if err != nil {
		return store.Account{}, err
	}
	a, err := m.Store.CreateAccount(ctx, store.CreateAccountParams{
		Slug: slug, DisplayName: displayName, Algo: string(algo),
	})
	if err != nil {
		return store.Account{}, err
	}
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return store.Account{}, err
	}
	sealed, err := m.Keyring.Encrypt(der, []byte(keyAAD))
	if err != nil {
		return store.Account{}, err
	}
	if err := m.Store.SetAccountKey(ctx, a.ID, kp.Fingerprint, sealed); err != nil {
		return store.Account{}, err
	}
	// SPEC §3.3: account-scoped actions require membership. Without this the
	// account is invisible to every owner surface — see membership.go.
	if err := GrantToAllOwners(ctx, m.Store, a.ID); err != nil {
		return store.Account{}, err
	}
	a.Fingerprint = kp.Fingerprint
	return a, nil
}

// LoadKeypair unseals an account's private key.
func (m *Manager) LoadKeypair(sealed []byte) (*Keypair, error) {
	der, err := m.Keyring.Decrypt(sealed, []byte(keyAAD))
	if err != nil {
		return nil, fmt.Errorf("identity: unseal: %w", err)
	}
	return ParsePKCS8(der)
}

// SignCard builds and signs the account's card (SPEC §9.3): BuildCard is the
// caller's job (card layout lives in contacts); this signs arbitrary card bytes
// with the account identity key — ECDSA ASN.1 DER or pure Ed25519, matching the
// envelope's pinned encodings.
func (m *Manager) SignCard(ctx context.Context, accountID string, cardText string) (string, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return "", err
	}
	sealed, err := m.Store.GetAccountSealedKey(ctx, a.ID)
	if err != nil {
		return "", err
	}
	if len(sealed) == 0 {
		// An identity that arrived in a data-only archive: its root is here and no
		// key is, so there is nothing to sign a card with until its wallet issues a
		// leaf to this host. Said here, because the alternative is a keyring
		// decrypt error on the invite landing page (PACT §9).
		return "", fmt.Errorf("identity: account %s holds no key on this host yet: install a leaf first", a.Slug)
	}
	kp, err := m.LoadKeypair(sealed)
	if err != nil {
		return "", err
	}
	sig, err := signBytes(kp, []byte(cardText))
	if err != nil {
		return "", err
	}
	return pactidentity.B64url(sig), nil
}
