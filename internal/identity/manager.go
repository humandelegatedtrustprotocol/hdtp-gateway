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

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// signBytes signs with the encodings HDTP §13.1 pins per algorithm: ECDSA over SHA-256 as ASN.1
// DER, Ed25519 per RFC 8032. It is the counterpart of VerifyBytes.
//
// It had an exported twin, `SignBytes`, "what produces the old-key endorsement a peer checks in
// `update_contact`" — key rotation, where a successor key had to be signed by its predecessor.
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
	// Store holds the accounts and the leaf ledger.
	Store store.Store
	// Keyring seals and opens every private key this package stores (AAD "accounts.key_sealed" for
	// the account row, "leaves.key_sealed" for a ledger row).
	Keyring *core.Keyring

	// beforeInstallWrites, when a test sets it, runs after an install has passed every check and
	// before its transaction: where two answers carrying one state are held together
	// (TestTwoAnswersTogetherInstallOnce).
	beforeInstallWrites func()
}

// ValidDisplayName is the one rule for an account's display name, on every door that names one
// (`account create`, the portal, an import's owner_name): the name is written into the account's
// card as one line (HDTP §3), and a control character in it is a card the writer refuses to write —
// a line break used to put a property of the NAME'S choosing into the card this node serves — so
// the account is refused before a key is made for it, not at the first request for a card it
// cannot have.
func ValidDisplayName(name string) error {
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("identity: a display name carries no control character (it is one line of the account's card)")
		}
	}
	return nil
}

// CreateAccount makes the account row, generates its keypair (AlgoP256 when algo is empty), seals
// the private key under the node keyring and binds the fingerprint and the sealed key to the row
// (SPEC §3.2), then grants every existing owner admin membership of it (GrantToAllOwners). A
// display name with a control character is refused before any key is made (ValidDisplayName).
// The account then has a key but no root and no leaf: it is served only after a wallet's leaf is
// installed (InstallLeaf). The steps are separate store writes, not one transaction.
func (m *Manager) CreateAccount(ctx context.Context, slug, displayName string, algo Algo) (store.Account, error) {
	if err := ValidDisplayName(displayName); err != nil {
		return store.Account{}, err
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

// LoadKeypair unseals the sealed private key of an account row (the accounts.key_sealed column,
// bound to that column by its AAD) and parses it. A ciphertext from another column, or one sealed
// under a master key this node no longer has, fails with "identity: unseal". The returned keypair
// carries no Leaf or Root; ActiveLeafKeypairs attaches those.
func (m *Manager) LoadKeypair(sealed []byte) (*Keypair, error) {
	der, err := m.Keyring.Decrypt(sealed, []byte(keyAAD))
	if err != nil {
		return nil, fmt.Errorf("identity: unseal: %w", err)
	}
	return ParsePKCS8(der)
}

// SignCard signs cardText with the account's own key and returns the signature as unpadded
// base64url (SPEC §9.3, HDTP §3). It builds nothing: the card's layout is the caller's job (it
// lives in contacts). The signature is ECDSA over SHA-256 as ASN.1 DER or pure Ed25519, matching
// the envelope's pinned encodings. An account whose key column is empty (an identity that arrived
// in a data-only archive, or whose last leaf expired and its key was destroyed) is refused with an
// error saying to install a leaf first; no key is made here.
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
		// decrypt error on the invite landing page (HDTP §9).
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
	return hdtpidentity.B64url(sig), nil
}
