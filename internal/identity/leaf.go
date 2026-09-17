package identity

// PACT 2.0 (PACT §2, §9, §14): the person is a certificate authority. This host
// holds, per account, the leaf the person's root issued and that leaf's key —
// the key that is the TLS certificate, signs every envelope and is sealed to.
// A leaf arrives through a certificate signing request the host makes and the
// wallet answers; it is installed only when it validates to the root the
// account already names (or names one for the first time), carries the key
// the request carried, and is newer than the leaf it replaces (§14.3).
//
// The ledger is the `leaves` table: pending while the wallet has not answered,
// current (exactly one), superseded with its key kept until notAfter so an
// envelope sealed to it still opens (§2), former with the key destroyed and
// the kid kept so such an envelope is answered certificate_renewed (§14.4).

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// leafKeyAAD binds a sealed leaf key to its column (SPEC §3.7, keyring AAD rule).
const leafKeyAAD = "leaves.key_sealed"

// Leaf states, as the migration constrains them.
const (
	LeafPending    = "pending"
	LeafCurrent    = "current"
	LeafSuperseded = "superseded"
	LeafFormer     = "former"
)

// CSR purposes. signup and upgrade both certify the account's EXISTING key —
// the difference is what the wallet is told; renew and move certify a fresh key.
const (
	PurposeSignup = "signup"
	PurposeRenew  = "renew"
	PurposeMove   = "move"
)

// RenewalWindow is how far ahead a host asks for a renewal (PACT §2: thirty days).
const RenewalWindow = 30 * 24 * time.Hour

// ToLib converts a keypair to the library's private key.
func ToLib(kp *Keypair) (*pactidentity.PrivateKey, error) {
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return nil, err
	}
	return pactidentity.ParsePKCS8(der)
}

// FromLib converts a library private key to a keypair.
func FromLib(k *pactidentity.PrivateKey) (*Keypair, error) {
	switch k.Alg {
	case "ed25519":
		return &Keypair{Algo: AlgoEd25519, Signer: k.Ed, Fingerprint: pactidentity.Fingerprint(k.Public.SPKI)}, nil
	case "p256":
		return &Keypair{Algo: AlgoP256, Signer: k.EC, Fingerprint: pactidentity.Fingerprint(k.Public.SPKI)}, nil
	}
	return nil, fmt.Errorf("identity: unsupported library key %q", k.Alg)
}

// SPKI is the DER SubjectPublicKeyInfo of a keypair's public half.
func SPKI(kp *Keypair) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return b, nil
}

// EndpointFor is the one address an account answers at (SPEC §5.2, PACT §14.1).
func EndpointFor(publicURL, slug string) string {
	if publicURL == "" {
		return ""
	}
	return strings.TrimRight(publicURL, "/") + "/a/" + slug + "/mcp"
}

// LeafKey is one leaf this host serves an account under, with its key open.
type LeafKey struct {
	Kid      string
	Leaf     []byte
	KP       *Keypair
	Current  bool
	NotAfter time.Time
	Endpoint string
	// notBefore of the leaf this key was issued under, for ordering.
	notBefore int64
}

// LeafNotBefore is the notBefore of the leaf this key was issued under; zero
// for a retiring 1.x key, which has no leaf. Picking the greatest is how a
// caller finds the most recently superseded key.
func (k LeafKey) LeafNotBefore() int64 { return k.notBefore }

func (m *Manager) sealLeafKey(kp *Keypair) ([]byte, error) {
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return nil, err
	}
	return m.Keyring.Encrypt(der, []byte(leafKeyAAD))
}

func (m *Manager) openLeafKey(sealed []byte) (*Keypair, error) {
	der, err := m.Keyring.Decrypt(sealed, []byte(leafKeyAAD))
	if err != nil {
		return nil, fmt.Errorf("identity: unseal leaf key: %w", err)
	}
	return ParsePKCS8(der)
}

// ActiveLeafKeypairs returns the current leaf's key first and every superseded
// key not yet past its notAfter, each with its leaf and the root attached. A
// superseded key past its notAfter is retired on this path: destroyed, its kid
// kept (§14.4).
//
// It closes the grace gap for a 2.0 RENEWAL, whose retiring key is in this
// ledger. A 1.x account's own rotation is not here — `Rotate` writes the
// prev_key columns and this reads `leaves` — so the 1.x grace gap is unchanged
// for an account that has never installed a leaf. Folding `Rotator`'s previous
// key in here would close that too; it is left alone because a 1.x account's
// grace is the 1.x path's business and this one has no claim on it.
func (m *Manager) ActiveLeafKeypairs(ctx context.Context, accountID string, now time.Time) ([]LeafKey, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, err
	}
	var out []LeafKey
	for _, l := range leaves {
		switch l.State {
		case LeafCurrent:
		case LeafSuperseded:
			if !now.Before(time.Unix(l.NotAfter, 0)) {
				// Past its notAfter: not served. The destruction of the key is
				// `RetireExpiredLeafKeys`, not this — a read that writes turns
				// every inbound request into a write, and swallowed the error of
				// the one thing here that must not fail quietly.
				continue
			}
		default:
			continue
		}
		if len(l.KeySealed) == 0 {
			continue
		}
		kp, err := m.openLeafKey(l.KeySealed)
		if err != nil {
			return nil, err
		}
		// A superseded row with a key and no leaf is the 1.x identity key a first
		// install retired (below): it has no chain to present, so it stays a 1.x
		// key — `tlsCertOf` self-signs for it — and it is served until its
		// notAfter so 1.x contacts still reach us while they re-pin.
		if len(l.Leaf) > 0 {
			kp.Leaf, kp.Root, kp.Protocol = l.Leaf, a.RootCert, 2
		} else {
			kp.Leaf, kp.Root, kp.Protocol = nil, nil, 1
		}
		lk := LeafKey{Kid: l.Kid, Leaf: l.Leaf, KP: kp, Current: l.State == LeafCurrent, NotAfter: time.Unix(l.NotAfter, 0), Endpoint: l.Endpoint, notBefore: l.NotBefore}
		if lk.Current {
			out = append([]LeafKey{lk}, out...)
		} else {
			out = append(out, lk)
		}
	}
	return out, nil
}

// AdoptCurrentLeafKey points the account row at the key of the leaf the ledger
// holds as current. An install is five writes and there is no transaction across
// them, so a failure between the ledger's move and the row's leaves the two
// disagreeing; the ledger is what validated, so it wins. The key is re-sealed
// under the account column's own AAD — the two columns bind their ciphertext to
// different names, and copying bytes between them would produce a row that
// cannot be opened again.
func (m *Manager) AdoptCurrentLeafKey(ctx context.Context, accountID string, lk LeafKey) error {
	der, err := MarshalPKCS8(lk.KP)
	if err != nil {
		return err
	}
	sealed, err := m.Keyring.Encrypt(der, []byte(keyAAD))
	if err != nil {
		return err
	}
	return m.Store.SetAccountLeafKey(ctx, accountID, lk.Kid, sealed, string(lk.KP.Algo))
}

// RetireExpiredLeafKeys destroys the key of every superseded leaf past its
// notAfter, keeping the kid so an envelope sealed to it is still answered
// `certificate_renewed` (§14.4). Called where the node already writes — adopting
// an account, installing a leaf — rather than on the read path every inbound
// request takes.
func (m *Manager) RetireExpiredLeafKeys(ctx context.Context, accountID string, now time.Time) error {
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return err
	}
	for _, l := range leaves {
		if l.State != LeafSuperseded || now.Before(time.Unix(l.NotAfter, 0)) {
			continue
		}
		if err := m.Store.RetireLeafKey(ctx, accountID, l.Kid); err != nil {
			return fmt.Errorf("identity: retire %s: %w", l.Kid, err)
		}
	}
	return nil
}

// FormerKids are the key identifiers of leaves once held and held no longer —
// what an envelope sealed to a retired key is answered `certificate_renewed`
// by (§14.4).
//
// A superseded leaf past its notAfter counts, whether or not its key has been
// destroyed yet: the answer turns on this endpoint having HELD that kid, which
// the row says either way, and the destruction is a write that happens on a
// write path (`RetireExpiredLeafKeys`). Reading it from the state alone is what
// lets the read path stop writing without changing a single answer on the wire.
func (m *Manager) FormerKids(ctx context.Context, accountID string, now time.Time) ([]string, error) {
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range leaves {
		switch {
		case l.State == LeafFormer:
			out = append(out, l.Kid)
		case l.State == LeafSuperseded && !now.Before(time.Unix(l.NotAfter, 0)):
			out = append(out, l.Kid)
		}
	}
	return out, nil
}

// Chain is [current leaf, root] for a 2.0 account; nil for a 1.x one.
func (m *Manager) Chain(ctx context.Context, accountID string) ([][]byte, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if a.Protocol != 2 {
		return nil, nil
	}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, err
	}
	for _, l := range leaves {
		if l.State == LeafCurrent {
			return [][]byte{l.Leaf, a.RootCert}, nil
		}
	}
	return nil, fmt.Errorf("identity: account %s is 2.0 but holds no current leaf", accountID)
}

// CSRResult is what the host hands the wallet.
type CSRResult struct {
	CSR               []byte // PKCS #10 DER
	Purpose           string
	Endpoint          string
	Kid               string // fingerprint of the key the request carries
	SuggestedNotAfter time.Time
	PreviousNotBefore *time.Time
}

// IssueCSR makes the request a wallet signs (PACT §9). signup and upgrade carry
// the account's existing key, so every 1.x pin of that key stays valid
// (Appendix C row 7); renew and move carry a fresh key, so a leaf key
// compromised without anyone noticing dies with its leaf (§9). The endpoint
// is the account's own unless the purpose is move. One pending request at a
// time: a new one replaces the last.
func (m *Manager) IssueCSR(ctx context.Context, accountID, purpose, endpoint string, now time.Time) (CSRResult, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return CSRResult{}, err
	}
	if endpoint == "" {
		return CSRResult{}, errors.New("identity: the request needs the endpoint the leaf will name")
	}
	if !pactidentity.IsNormalHTTPS(endpoint) {
		return CSRResult{}, fmt.Errorf("identity: %q is not an https URL in normal form (PACT §14.1)", endpoint)
	}
	// "The endpoint is the account's own unless the purpose is move" was the
	// documented rule and nothing enforced it, so `csr renew -endpoint <other>`
	// was a move in everything but name — and a move re-pins every contact.
	// The address the identity already answers at is the one its current leaf
	// names; before the first leaf there is nothing to depart from.
	if purpose != PurposeMove {
		if leaves, lerr := m.Store.ListLeaves(ctx, accountID); lerr == nil {
			for _, l := range leaves {
				if l.State == LeafCurrent && l.Endpoint != "" && l.Endpoint != endpoint {
					return CSRResult{}, fmt.Errorf("identity: this identity answers at %s; a request naming %s is a move, so ask for one (PACT §5.3)", l.Endpoint, endpoint)
				}
			}
		}
	}
	var kp *Keypair
	switch purpose {
	case PurposeSignup:
		sealed, err := m.Store.GetAccountSealedKey(ctx, accountID)
		if err != nil {
			return CSRResult{}, err
		}
		if kp, err = m.LoadKeypair(sealed); err != nil {
			return CSRResult{}, err
		}
	case PurposeRenew, PurposeMove:
		// A fresh key either way, so a leaf key compromised without anyone
		// noticing dies with its leaf (§9).
		if kp, err = Generate(Algo(a.Algo)); err != nil {
			return CSRResult{}, err
		}
	default:
		return CSRResult{}, fmt.Errorf("identity: unknown purpose %q (signup|renew|move|upgrade)", purpose)
	}
	lib, err := ToLib(kp)
	if err != nil {
		return CSRResult{}, err
	}
	csr, err := pactidentity.CSRNew(a.DisplayName, lib, endpoint, "")
	if err != nil {
		return CSRResult{}, fmt.Errorf("identity: csr: %w", err)
	}
	sealed, err := m.sealLeafKey(kp)
	if err != nil {
		return CSRResult{}, err
	}
	if _, err := m.Store.DeleteLeavesByState(ctx, accountID, LeafPending); err != nil {
		return CSRResult{}, err
	}
	if err := m.Store.InsertLeaf(ctx, store.Leaf{AccountID: accountID, Kid: kp.Fingerprint, KeySealed: sealed, State: LeafPending, Endpoint: endpoint, CreatedAt: now.Unix()}); err != nil {
		// The key already names a leaf of this account (an upgrade of a key
		// that is already a leaf's, or a renewal that generated no new key).
		return CSRResult{}, fmt.Errorf("identity: a leaf for key %s already exists: %w", kp.Fingerprint, err)
	}
	res := CSRResult{CSR: csr, Purpose: purpose, Endpoint: endpoint, Kid: kp.Fingerprint, SuggestedNotAfter: now.Add(365 * 24 * time.Hour)}
	if leaves, err := m.Store.ListLeaves(ctx, accountID); err == nil {
		for _, l := range leaves {
			if l.State == LeafCurrent {
				t := time.Unix(l.NotBefore, 0)
				res.PreviousNotBefore = &t
			}
		}
	}
	return res, nil
}

// InstallResult is what changed when a leaf was installed.
type InstallResult struct {
	AccountID       string
	Slug            string
	Protocol        int
	RootFingerprint string
	Kid             string // the new current leaf's key id
	OldKid          string // the superseded leaf's key id, "" on a first install
	OldEndpoint     string // the superseded leaf's endpoint; a difference is a move (PACT §5.3)
	KeyChanged      bool
	FirstInstall    bool
	Endpoint        string
	NotBefore       time.Time
	NotAfter        time.Time
	OldKP           *Keypair // the superseded key, for the 1.x rotation toward 1.x pins
	NewKP           *Keypair
}

// InstallLeaf installs a wallet-issued chain (PACT §14.2 in full): the leaf
// must validate to the root the account names — or, on a first install, to the
// root it will name from now on — must name the endpoint the pending request
// named, must carry the pending request's key, and must be newer than the
// current leaf (§14.3). Then the current leaf is superseded, the pending one
// becomes current, the account's key column points at it, and every contact's
// chain-sent mark is cleared so each sees the new chain once (§13.2).
func (m *Manager) InstallLeaf(ctx context.Context, accountID string, chain [][]byte, now time.Time) (InstallResult, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return InstallResult{}, err
	}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return InstallResult{}, err
	}
	var pending, current *store.Leaf
	for i := range leaves {
		switch leaves[i].State {
		case LeafPending:
			pending = &leaves[i]
		case LeafCurrent:
			current = &leaves[i]
		}
	}
	if pending == nil {
		return InstallResult{}, errors.New("identity: no certificate request is pending for this account; run `account csr` first")
	}
	vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: now, ExpectedRoot: a.RootFingerprint, ExpectedEndpoint: pending.Endpoint})
	if !vr.OK {
		return InstallResult{}, fmt.Errorf("identity: chain refused by rule %d: %s", vr.Rule, vr.Reason)
	}
	if got := pactidentity.Fingerprint(vr.LeafKey.SPKI); got != pending.Kid {
		return InstallResult{}, fmt.Errorf("identity: the leaf carries key %s, not the requested %s", got, pending.Kid)
	}
	if current != nil {
		cmp, err := pactidentity.CompareLeaves(current.Leaf, chain[0])
		if err != nil {
			return InstallResult{}, fmt.Errorf("identity: %w", err)
		}
		if cmp != "newer" {
			return InstallResult{}, fmt.Errorf("identity: the leaf is %s relative to the current one; a leaf must be newer (PACT §14.3)", cmp)
		}
	}
	kp, err := m.openLeafKey(pending.KeySealed)
	if err != nil {
		return InstallResult{}, err
	}
	res := InstallResult{
		AccountID: a.ID, Slug: a.Slug, Protocol: 2, RootFingerprint: vr.RootFingerprint, Kid: pending.Kid,
		FirstInstall: a.Protocol != 2, Endpoint: vr.Endpoint, NotBefore: vr.Leaf.NotBefore, NotAfter: vr.Leaf.NotAfter, NewKP: kp,
	}
	if current != nil {
		res.OldKid, res.OldEndpoint = current.Kid, current.Endpoint
		res.KeyChanged = current.Kid != pending.Kid
		if len(current.KeySealed) > 0 {
			if res.OldKP, err = m.openLeafKey(current.KeySealed); err != nil {
				return InstallResult{}, err
			}
		}
		if res.KeyChanged {
			if err := m.Store.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: current.Kid, Leaf: current.Leaf, NotBefore: current.NotBefore, NotAfter: current.NotAfter, State: LeafSuperseded, Endpoint: current.Endpoint}); err != nil {
				return InstallResult{}, err
			}
		} else {
			// The same key under a newer leaf (an upgrade of a 1.x rotation's
			// key, or a wallet that reused one): there is nothing to keep.
			if _, err := m.Store.DeleteLeavesByState(ctx, accountID, LeafCurrent); err != nil {
				return InstallResult{}, err
			}
		}
	} else if a.Fingerprint != "" && a.Fingerprint != pending.Kid {
		// A first install that changes the key (a renewal requested as the first
		// leaf): the 1.x identity key retires like a superseded leaf would, kept
		// for a year so 1.x contacts can still reach us while they re-pin.
		sealedOld, err := m.Store.GetAccountSealedKey(ctx, accountID)
		if err != nil {
			return InstallResult{}, fmt.Errorf("identity: read the key being retired: %w", err)
		}
		oldKP, err := m.LoadKeypair(sealedOld)
		if err != nil {
			return InstallResult{}, fmt.Errorf("identity: open the key being retired: %w", err)
		}
		res.OldKid, res.OldKP, res.KeyChanged = a.Fingerprint, oldKP, true
		sealed, err := m.sealLeafKey(oldKP)
		if err != nil {
			return InstallResult{}, fmt.Errorf("identity: reseal the key being retired: %w", err)
		}
		// NotBefore is the account's own start, unknown here, so it stays zero: this
		// row is the oldest key by construction, which is what the ordering wants.
		if err := m.Store.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: a.Fingerprint, KeySealed: sealed, NotAfter: now.Add(365 * 24 * time.Hour).Unix(), State: LeafSuperseded, Endpoint: vr.Endpoint, CreatedAt: now.Unix()}); err != nil {
			return InstallResult{}, fmt.Errorf("identity: keep the key being retired: %w", err)
		}
	}
	if err := m.Store.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: pending.Kid, Leaf: chain[0], NotBefore: vr.Leaf.NotBefore.Unix(), NotAfter: vr.Leaf.NotAfter.Unix(), State: LeafCurrent, Endpoint: vr.Endpoint}); err != nil {
		return InstallResult{}, err
	}
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return InstallResult{}, err
	}
	sealedAcct, err := m.Keyring.Encrypt(der, []byte(keyAAD))
	if err != nil {
		return InstallResult{}, err
	}
	if err := m.Store.SetAccountLeafKey(ctx, a.ID, pending.Kid, sealedAcct, string(kp.Algo)); err != nil {
		return InstallResult{}, err
	}
	if err := m.Store.SetAccountProtocol(ctx, a.ID, 2, vr.RootFingerprint, chain[1]); err != nil {
		return InstallResult{}, err
	}
	if err := m.Store.ClearChainSentKids(ctx, a.ID); err != nil {
		return InstallResult{}, err
	}
	kp.Leaf, kp.Root, kp.Protocol = chain[0], chain[1], 2
	return res, nil
}

// CertificateInfo is `account certificate`'s answer.
type CertificateInfo struct {
	Protocol        int
	RootFingerprint string
	Chain           [][]byte
	Kid             string
	Endpoint        string
	NotBefore       time.Time
	NotAfter        time.Time
	RenewalDue      bool
	PendingCSR      string // the pending request's key id, "" when none
	Superseded      []string
	Former          []string
}

// Certificate reports an account's certificate state; renewal is due thirty
// days ahead of the leaf's notAfter (PACT §2).
func (m *Manager) Certificate(ctx context.Context, accountID string, now time.Time) (CertificateInfo, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return CertificateInfo{}, err
	}
	info := CertificateInfo{Protocol: int(a.Protocol), RootFingerprint: a.RootFingerprint}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return CertificateInfo{}, err
	}
	for _, l := range leaves {
		switch l.State {
		case LeafCurrent:
			info.Chain = [][]byte{l.Leaf, a.RootCert}
			info.Kid, info.Endpoint = l.Kid, l.Endpoint
			info.NotBefore, info.NotAfter = time.Unix(l.NotBefore, 0).UTC(), time.Unix(l.NotAfter, 0).UTC()
			info.RenewalDue = now.Add(RenewalWindow).After(info.NotAfter)
		case LeafPending:
			info.PendingCSR = l.Kid
		case LeafSuperseded:
			// Past its notAfter it is reported as former, whether or not its key
			// has been destroyed yet — the same rule `FormerKids` reads, so the
			// two views of the ledger cannot disagree.
			if now.Before(time.Unix(l.NotAfter, 0)) {
				info.Superseded = append(info.Superseded, l.Kid)
			} else {
				info.Former = append(info.Former, l.Kid)
			}
		case LeafFormer:
			info.Former = append(info.Former, l.Kid)
		}
	}
	return info, nil
}

// RestoreLeaf installs a leaf that came back from a backup (identity.Backup
// version 2) as the account's current leaf: the key sealed under this node's
// keyring, the ledger row current, the root beside the account. kp carries
// Leaf and Root as OpenIdentity attached them.
func (m *Manager) RestoreLeaf(ctx context.Context, accountID string, kp *Keypair, _ []byte) error {
	if kp.Protocol != 2 || len(kp.Leaf) == 0 || len(kp.Root) == 0 {
		return errors.New("identity: the key carries no leaf to restore")
	}
	vr := pactidentity.ValidateChain([][]byte{kp.Leaf, kp.Root}, pactidentity.ChainOpts{Now: time.Now()})
	if !vr.OK {
		return fmt.Errorf("identity: the backed-up chain is refused by rule %d: %s", vr.Rule, vr.Reason)
	}
	if pactidentity.Fingerprint(vr.LeafKey.SPKI) != kp.Fingerprint {
		return errors.New("identity: the backed-up key is not the leaf's")
	}
	sealed, err := m.sealLeafKey(kp)
	if err != nil {
		return err
	}
	if err := m.Store.InsertLeaf(ctx, store.Leaf{AccountID: accountID, Kid: kp.Fingerprint, Leaf: kp.Leaf, KeySealed: sealed,
		NotBefore: vr.Leaf.NotBefore.Unix(), NotAfter: vr.Leaf.NotAfter.Unix(), State: LeafCurrent, Endpoint: vr.Endpoint, CreatedAt: time.Now().Unix()}); err != nil {
		return err
	}
	return m.Store.SetAccountProtocol(ctx, accountID, 2, vr.RootFingerprint, kp.Root)
}
