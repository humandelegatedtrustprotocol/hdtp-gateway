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
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	pactidentity "github.com/pact-cloud/pact-identity/go"
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

// CSR purposes. signup certifies the key the account was created with, or a fresh one when the
// account holds none (it arrived in a bundle, and a bundle carries no leaf key); renew and move
// always certify a fresh key.
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

// FromLib converts a library private key to a keypair: ToLib's inverse.
//
// Nothing in this module calls it, and it is not dead. The cloud's conformance battery
// (../pact-cloud/gateway/conformance) drives this node's own outbound client as its reference
// peer, and builds that peer's keypair from a library key through here. `make dependents` is the
// gate that compiles it; a scan of this module alone reads this as unused, and one such scan
// deleted it on 2026-09-19 before that gate said otherwise.
func FromLib(k *pactidentity.PrivateKey) (*Keypair, error) {
	switch k.Alg {
	case "ed25519":
		return &Keypair{Algo: AlgoEd25519, Signer: k.Ed, Fingerprint: pactidentity.Fingerprint(k.Public.SPKI)}, nil
	case "p256":
		return &Keypair{Algo: AlgoP256, Signer: k.EC, Fingerprint: pactidentity.Fingerprint(k.Public.SPKI)}, nil
	}
	return nil, fmt.Errorf("identity: unsupported library key %q", k.Alg)
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
}

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

// ActiveLeafKeypairs returns the current leaf's key first and every superseded key not yet past
// its notAfter, each with its leaf and the root attached. That is what closes the gap after a
// RENEWAL: a contact that has not heard yet still seals to the superseded leaf, and the host
// keeps that key until the leaf's notAfter so the envelope opens (PACT §14.4).
//
// A superseded key past its notAfter is simply not returned. Destroying it is
// `RetireExpiredLeafKeys`, on a write path — this is a read, taken by every inbound request.
func (m *Manager) ActiveLeafKeypairs(ctx context.Context, accountID string, now time.Time) ([]LeafKey, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return m.ActiveLeafKeypairsFor(ctx, a, now)
}

// ActiveLeafKeypairsFor is the same read for a caller that already holds the
// account row. The one on the inbound path does — it is read to answer the
// envelope — and reading it twice per message bought nothing.
func (m *Manager) ActiveLeafKeypairsFor(ctx context.Context, a store.Account, now time.Time) ([]LeafKey, error) {
	accountID := a.ID
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, err
	}
	var out []LeafKey
	for _, l := range leaves {
		switch l.State {
		case LeafCurrent, LeafSuperseded:
			if !now.Before(time.Unix(l.NotAfter, 0)) {
				// Past its notAfter: not served, and that holds for the CURRENT leaf as much as a
				// superseded one. It used to be checked for superseded leaves only, so a leaf
				// nobody renewed went on being presented and its key went on opening envelopes
				// for as long as the process ran. The destruction of the key is
				// `RetireExpiredLeafKeys`, not this — a read that writes turns every inbound
				// request into a write, and swallowed the error of the one thing here that must
				// not fail quietly.
				continue
			}
		default:
			continue
		}
		// A row with a key and no leaf is not a leaf's key, and nothing can have been sealed to it:
		// a card carries a leaf, so a key that never had one was never anybody's target. Installs
		// stopped making such rows on 2026-09-19 (they held the pre-leaf account key, for 1.x
		// contacts); a store from before then may still hold one, and it is not served.
		if len(l.KeySealed) == 0 || len(l.Leaf) == 0 {
			continue
		}
		kp, err := m.openLeafKey(l.KeySealed)
		if err != nil {
			return nil, err
		}
		kp.Leaf, kp.Root = l.Leaf, a.RootCert
		lk := LeafKey{Kid: l.Kid, Leaf: l.Leaf, KP: kp, Current: l.State == LeafCurrent, NotAfter: time.Unix(l.NotAfter, 0), Endpoint: l.Endpoint}
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

// RetiredLeaf is one leaf whose key RetireExpiredLeafKeys destroyed.
type RetiredLeaf struct {
	Kid string
	// Current says it was the leaf the account served under. The account's own copy of the key
	// went with it, so the account now awaits a leaf and must stop being served.
	Current bool
}

// RetireExpiredLeafKeys destroys the key of every leaf past its notAfter, keeping the kid so an
// envelope sealed to it is still answered `certificate_renewed` (§14.4).
//
// EVERY leaf, the current one included. An expired leaf is refused by every verifier (PACT §14.2
// rule 4), so its key can do nothing legitimate, and a leaf is the root's trust in this host UNTIL
// A DATE: past the date, the key is something this host was never meant to still hold. It used to
// retire only `superseded` leaves, so the key of a leaf that simply ran out — nobody renewed it —
// stayed in the store for good, in the ledger row and again in the account's.
//
// A renewal after expiry loses nothing by this: `renew` always mints a fresh key.
//
// Order matters for a current leaf, because these are two writes and no transaction. The account's
// copy goes FIRST: if the second write fails, the account is keyless — which the node reads as
// awaiting a leaf — and the ledger row is still `current` and still expired, so the next pass
// finishes the job. The other order leaves a key in the account row that nothing would ever find.
//
// Called where the node already writes — at boot, on the hourly sweep, when an account is adopted —
// and never on the read path every inbound request takes.
func (m *Manager) RetireExpiredLeafKeys(ctx context.Context, accountID string, now time.Time) ([]RetiredLeaf, error) {
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, err
	}
	var out []RetiredLeaf
	for _, l := range leaves {
		if l.State != LeafCurrent && l.State != LeafSuperseded {
			continue
		}
		if now.Before(time.Unix(l.NotAfter, 0)) {
			continue
		}
		current := l.State == LeafCurrent
		if current {
			if err := m.Store.ClearAccountKey(ctx, accountID); err != nil {
				return out, fmt.Errorf("identity: retire %s: %w", l.Kid, err)
			}
		}
		if err := m.Store.RetireLeafKey(ctx, accountID, l.Kid); err != nil {
			return out, fmt.Errorf("identity: retire %s: %w", l.Kid, err)
		}
		out = append(out, RetiredLeaf{Kid: l.Kid, Current: current})
	}
	// NULL is not destroyed: the key's bytes are still in the database's files until they are
	// overwritten (store.Store.Scrub).
	if len(out) > 0 {
		if err := m.Store.Scrub(ctx); err != nil {
			return out, fmt.Errorf("identity: the retired keys are cleared and their bytes may remain on disk: %w", err)
		}
	}
	return out, nil
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

// Chain is [current leaf, root], or nil for an account the wallet has not issued a leaf to yet.
func (m *Manager) Chain(ctx context.Context, accountID string) ([][]byte, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if !a.HasRoot() {
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
	// State is the random value a web wallet's answer must carry back (PACT §9.1): 32 bytes,
	// base64url, 43 characters. The host keeps only its SHA-256 (migration 0041); an answer is
	// accepted once, with it (InstallWalletLeaf).
	State string
	// Warnings are what the request did not finish although it is made: a replaced request's key
	// whose bytes could not yet be scrubbed (store.Store.Scrub).
	Warnings []Warning
}

// IssueCSR makes the request a wallet signs (PACT §9).
//
// `signup` carries the key this host was created with, when it has one: at creation nothing has
// been signed yet, so there is no reason to mint a second key and leave the first unused. A host
// that holds NO key — an account that arrived as a data-only import, its root and its contacts
// carried and its leaf key left behind on the host that issued it (PACT §9) — mints one, which is
// the difference between "one `account csr` away from serving" and a dead end.
//
// `renew` and `move` always carry a fresh key, so a leaf key compromised without anyone noticing
// dies with its leaf (§9). The endpoint is the account's own unless the purpose is move. One
// pending request at a time: a new one replaces the last.
//
// `upgrade` was the fourth purpose and went with 1.x: it carried the identity's existing key so
// that every pin of that key stayed valid, and there is no such pin any more.
func (m *Manager) IssueCSR(ctx context.Context, accountID, purpose, endpoint string, now time.Time) (CSRResult, error) {
	return m.issueCSR(ctx, accountID, purpose, endpoint, "", now)
}

// IssueWalletCSR is IssueCSR for a request sent to a web wallet at `walletOrigin` (PACT §9.1): the
// same request, with the wallet it went to recorded beside the state's hash. The web wallet does not
// take `signup` (O8 of the identity-boundary design), so neither does this.
func (m *Manager) IssueWalletCSR(ctx context.Context, accountID, purpose, endpoint, walletOrigin string, now time.Time) (CSRResult, error) {
	if purpose != PurposeRenew && purpose != PurposeMove {
		return CSRResult{}, fmt.Errorf("identity: a web wallet signs a renew or a move, not %q; a first leaf comes from the CLI wallet: %w", purpose, ErrLeafRefused)
	}
	if walletOrigin == "" {
		return CSRResult{}, errors.New("identity: a request for a web wallet names the wallet")
	}
	return m.issueCSR(ctx, accountID, purpose, endpoint, walletOrigin, now)
}

func (m *Manager) issueCSR(ctx context.Context, accountID, purpose, endpoint, walletOrigin string, now time.Time) (CSRResult, error) {
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
	// The core's address rule, the one a wallet applies before it certifies an endpoint and a peer
	// before it takes one into a card: a request naming an address it refuses (a loopback, private
	// or local host, as a public_url of localhost makes) is refused here, in its words, rather than
	// handed to a wallet that will refuse it.
	if ok, why := pactidentity.AddressGuard(endpoint, "", false); !ok {
		return CSRResult{}, fmt.Errorf("identity: %s: %s; set public_url to the address people reach this node at: %w: %w", endpoint, why, ErrEndpointRefused, ErrLeafRefused)
	}
	// An address an identity left stays reserved until the last leaf issued for it expires (PACT
	// §9, migration 0040). A request naming it would ask a wallet for a leaf at an address this
	// node must not assign; the account slug is guarded where accounts are created (the store).
	if vacated, verr := m.Store.LiveVacatedEndpoint(ctx, endpoint, now.Unix()); verr != nil {
		return CSRResult{}, verr
	} else if vacated {
		return CSRResult{}, fmt.Errorf("identity: %s was vacated by an identity that left this node; it stays reserved until the last leaf issued for it expires (PACT §9): %w", endpoint, store.ErrAddressVacated)
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
		if len(sealed) == 0 {
			// A data-only import: there is no key here to certify, so this host makes its own.
			if kp, err = Generate(Algo(a.Algo)); err != nil {
				return CSRResult{}, err
			}
			break
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
		return CSRResult{}, fmt.Errorf("identity: unknown purpose %q (signup|renew|move)", purpose)
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
	state, err := newRequestState()
	if err != nil {
		return CSRResult{}, err
	}
	// The replacement is one step: the pending request goes and this one takes its place, or
	// nothing changes. Two requests made together used to interleave the three writes and leave
	// two pending rows (migration 0044 now refuses a second one).
	var replaced int64
	err = m.Store.Atomically(ctx, func(tx store.Store) error {
		if err := tx.LockAccount(ctx, accountID); err != nil {
			return err
		}
		n, err := tx.DeleteLeavesByState(ctx, accountID, LeafPending)
		if err != nil {
			return err
		}
		replaced = n
		if err := tx.InsertLeaf(ctx, store.Leaf{AccountID: accountID, Kid: kp.Fingerprint, KeySealed: sealed, State: LeafPending, Endpoint: endpoint, CreatedAt: now.Unix()}); err != nil {
			// The key already names a leaf of this account (an upgrade of a key
			// that is already a leaf's, or a renewal that generated no new key).
			return fmt.Errorf("identity: a leaf for key %s already exists: %w", kp.Fingerprint, err)
		}
		return tx.SetLeafRequest(ctx, accountID, kp.Fingerprint, stateHash(state), walletOrigin)
	})
	if err != nil {
		return CSRResult{}, err
	}
	res := CSRResult{CSR: csr, Purpose: purpose, Endpoint: endpoint, Kid: kp.Fingerprint, SuggestedNotAfter: now.Add(365 * 24 * time.Hour), State: state}
	// The replaced request's key goes with its row, bytes and all (store.Store.Scrub).
	if replaced > 0 {
		if err := m.Store.Scrub(ctx); err != nil {
			res.Warnings = append(res.Warnings, WarnUnscrubbed)
		}
	}
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
	RootFingerprint string
	Kid             string // the new current leaf's key id
	OldKid          string // the superseded leaf's key id, "" on a first install
	OldEndpoint     string // where the identity answered before this leaf, when this host's ledger knows
	// OldNotAfter is when the leaf this one follows expires, when this host's ledger knows it; zero
	// after an import that carried no ledger. It is the date a move notice gives (MoveNotice).
	OldNotAfter time.Time
	// Moved says this leaf put the identity at an address its contacts do not know yet, so they
	// are owed `update_contact` from it (PACT §5.3, §9). See InstallLeaf for how it is decided.
	Moved        bool
	KeyChanged   bool
	FirstInstall bool
	Endpoint     string
	NotBefore    time.Time
	NotAfter     time.Time
	// Retired names every superseded leaf whose key this node could not open, and which was
	// therefore made `former` — key destroyed, kid kept — instead of being kept to serve.
	// Empty on an ordinary renewal. Not empty after the master key was lost: see InstallLeaf.
	Retired []string
	// HandshakesDue counts the contacts an import brought that this leaf's campaign owes the
	// handshake (Campaign.Owes, PACT §9.2). The caller starts the campaign when it is not zero,
	// moved or not: an import into an identity already served here is followed by a renewal at the
	// same address, and that campaign walks these contacts and nobody else.
	HandshakesDue int
	// Warnings are what the install did not finish although the leaf is installed: a destroyed
	// key whose bytes could not yet be scrubbed from the store's files (store.Store.Scrub). The
	// caller reports each one.
	Warnings []Warning
}

// InstallLeaf installs a wallet-issued chain (PACT §14.2 in full): the leaf
// must validate to the root the account names — or, on a first install, to the
// root it will name from now on — must name the endpoint the pending request
// named, must carry the pending request's key, and must be newer than the
// current leaf (§14.3). Then the current leaf is superseded, the pending one
// becomes current, the account's key column points at it, and every contact's
// chain-sent mark is cleared so each sees the new chain once (§13.2).
func (m *Manager) InstallLeaf(ctx context.Context, accountID string, chain [][]byte, now time.Time) (InstallResult, error) {
	return m.installLeaf(ctx, accountID, chain, "", now)
}

// InstallWalletLeaf is InstallLeaf for a web wallet's answer (PACT §9.1): "A host MUST accept an
// answer only once, only with the state it minted for a pending request, and only a chain whose
// leaf carries that request's key and validates at its endpoint." The state is checked before the
// chain is, and consumed — in the statement that checks it — only once the chain has passed, so a
// refused chain leaves the request answerable.
func (m *Manager) InstallWalletLeaf(ctx context.Context, accountID string, chain [][]byte, state string, now time.Time) (InstallResult, error) {
	if state == "" {
		return InstallResult{}, fmt.Errorf("identity: an answer from a web wallet carries the request's state: %w", ErrRequestState)
	}
	return m.installLeaf(ctx, accountID, chain, state, now)
}

func (m *Manager) installLeaf(ctx context.Context, accountID string, chain [][]byte, state string, now time.Time) (InstallResult, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return InstallResult{}, err
	}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return InstallResult{}, err
	}
	var pending, current *store.Leaf
	pendings := 0
	for i := range leaves {
		switch leaves[i].State {
		case LeafPending:
			pending = &leaves[i]
			pendings++
		case LeafCurrent:
			current = &leaves[i]
		}
	}
	if pendings > 1 {
		// Migration 0044 makes this impossible; a ledger that holds it anyway is not one to guess in.
		return InstallResult{}, fmt.Errorf("identity: %d certificate requests are pending for this account and one is expected; run `account csr` again", pendings)
	}
	if pending == nil {
		if state != "" {
			return InstallResult{}, fmt.Errorf("identity: no certificate request is pending for this account, so no answer is expected (it may have been answered already): %w", ErrRequestState)
		}
		return InstallResult{}, fmt.Errorf("identity: no certificate request is pending for this account; run `account csr` first: %w", ErrLeafRefused)
	}
	if state != "" && (len(pending.RequestStateHash) == 0 || subtle.ConstantTimeCompare(pending.RequestStateHash, stateHash(state)) != 1) {
		return InstallResult{}, fmt.Errorf("identity: the answer's state is not the pending request's (another request, or one already answered): %w", ErrRequestState)
	}
	vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: now, ExpectedRoot: a.RootFingerprint, ExpectedEndpoint: pending.Endpoint})
	if !vr.OK {
		return InstallResult{}, fmt.Errorf("identity: chain refused by rule %d: %s: %w", vr.Rule, vr.Reason, ErrLeafRefused)
	}
	if got := pactidentity.Fingerprint(vr.LeafKey.SPKI); got != pending.Kid {
		return InstallResult{}, fmt.Errorf("identity: the leaf carries key %s, not the requested %s: %w", got, pending.Kid, ErrLeafRefused)
	}
	if current != nil {
		cmp, err := pactidentity.CompareLeaves(current.Leaf, chain[0])
		if err != nil {
			return InstallResult{}, fmt.Errorf("identity: %w: %w", err, ErrLeafRefused)
		}
		if cmp != "newer" {
			return InstallResult{}, fmt.Errorf("identity: the leaf is %s relative to the current one; a leaf must be newer (PACT §14.3): %w", cmp, ErrLeafRefused)
		}
	}
	// The answer has passed every check. What follows is one transaction: the answer is used —
	// once — and installed, or neither. Two answers carrying one state both reach this point only
	// if they arrive together; the statement that consumes the state lets exactly one through, and
	// the other's transaction writes nothing.
	if m.beforeInstallWrites != nil {
		m.beforeInstallWrites()
	}
	kp, err := m.openLeafKey(pending.KeySealed)
	if err != nil {
		return InstallResult{}, err
	}
	res := InstallResult{
		AccountID: a.ID, Slug: a.Slug, RootFingerprint: vr.RootFingerprint, Kid: pending.Kid,
		FirstInstall: !a.HasRoot(), Endpoint: vr.Endpoint, NotBefore: vr.Leaf.NotBefore, NotAfter: vr.Leaf.NotAfter,
	}
	if current != nil {
		res.OldKid, res.OldEndpoint = current.Kid, current.Endpoint
		res.KeyChanged = current.Kid != pending.Kid
	} else if a.Fingerprint != "" && a.Fingerprint != pending.Kid {
		// A first leaf over a key other than the one the account names: requested as a renewal or
		// a move rather than a signup, or installed after a data-only import, where the account
		// names the key its PREVIOUS host served under and does not hold it (a leaf key belongs to
		// the host it was issued to, PACT §9; `TestFirstLeafAfterADataOnlyImport` walks that move).
		//
		// Either way there is nothing to retire. PACT §14.4 keeps a superseded LEAF's key until
		// its notAfter, so an envelope sealed to it is answered `certificate_renewed` — and the
		// key being replaced here was never a leaf. Before the first leaf an identity has no card
		// and cannot be served, so no 2.0 sender can have sealed anything to it. It used to be
		// kept for a year anyway, as a leafless ledger row that was loaded and served, "so 1.x
		// contacts still reach us while they re-pin"; those were the only callers who ever held
		// it. `SetAccountLeafKey` below overwrites the sealed key, which is what destroys it.
		res.KeyChanged = true
	}
	// Did the identity move? The caller starts the move campaign on the answer, and it used to work
	// the answer out for itself from `OldEndpoint` — which was read from the CURRENT leaf's row and
	// so was empty whenever there was none. That is every install that follows an import: a
	// bundle's ledger arrives as `former` rows (no bundle carries a leaf key), and the cloud's leave
	// archive carries no ledger at all. So the one install that is a move by construction — a new
	// host's first leaf for an identity that lived somewhere else, PACT §9's own sequence — started
	// no campaign, and every contact went on calling an address the identity had left.
	//
	//   - a current leaf: moved if the new leaf names another endpoint;
	//   - no current leaf, but the ledger remembers one: moved if the LAST one named another
	//     endpoint. A restore onto the same address, or a renewal after a leaf ran out, is not;
	//   - a root and no ledger at all: it arrived from another host with its name and nothing
	//     else. Moved. If its contacts happen to hold this very address already, what they
	//     receive is a card refresh, which costs nothing.
	if prev := departedFrom(leaves); prev != nil {
		res.OldEndpoint = prev.Endpoint
		res.OldNotAfter = time.Unix(prev.NotAfter, 0).UTC()
	}
	res.Moved = moves(a, leaves, res.Endpoint)

	// A superseded leaf is kept for one reason: to be SERVED, as a guest, until its notAfter, so an
	// envelope still sealed to it is answered `certificate_renewed` (PACT §14.4). A key this node
	// cannot open cannot be served, and the only way that happens is that the master key it was
	// sealed under is gone. Such a row is retired — key destroyed, kid kept — rather than kept as a
	// guest that fails every listing of this account's keys and takes the account down with it.
	//
	// Until 2026-09-19 this was a dead end instead. The install unsealed the outgoing leaf's key
	// into `InstallResult.OldKP` and failed if it could not; nothing read that field — it fed the
	// 1.x rotation fan-out, which signed with the old key — so a node that had lost its master key
	// could not install the one thing that recovers it, for the sake of a value nobody used. Under
	// 2.0 that recovery is real: the identity is the root, the root is in the wallet, and the
	// wallet can certify this host again.
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return InstallResult{}, err
	}
	sealedAcct, err := m.Keyring.Encrypt(der, []byte(keyAAD))
	if err != nil {
		return InstallResult{}, err
	}
	var retired []string
	err = m.Store.Atomically(ctx, func(tx store.Store) error {
		retired, res.HandshakesDue = nil, 0
		if state != "" {
			ok, err := tx.ConsumeLeafRequest(ctx, a.ID, pending.Kid, stateHash(state))
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("identity: the request was answered already: %w", ErrRequestState)
			}
		}
		if current != nil {
			if res.KeyChanged {
				if err := tx.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: current.Kid, Leaf: current.Leaf, NotBefore: current.NotBefore, NotAfter: current.NotAfter, State: LeafSuperseded, Endpoint: current.Endpoint}); err != nil {
					return err
				}
			} else if _, err := tx.DeleteLeavesByState(ctx, accountID, LeafCurrent); err != nil {
				// The same key under a newer leaf — a wallet that re-issued over the key it was
				// given rather than a fresh one: there is nothing to keep.
				return err
			}
		}
		for _, l := range leaves {
			outgoing := current != nil && res.KeyChanged && l.Kid == current.Kid
			if l.State != LeafSuperseded && !outgoing {
				continue
			}
			if len(l.KeySealed) > 0 {
				if _, oerr := m.openLeafKey(l.KeySealed); oerr == nil {
					continue
				}
			}
			if err := tx.RetireLeafKey(ctx, a.ID, l.Kid); err != nil {
				return err
			}
			retired = append(retired, l.Kid)
		}
		if err := tx.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: pending.Kid, Leaf: chain[0], NotBefore: vr.Leaf.NotBefore.Unix(), NotAfter: vr.Leaf.NotAfter.Unix(), State: LeafCurrent, Endpoint: vr.Endpoint}); err != nil {
			return err
		}
		// The install's decision, kept with the leaf: a campaign resumed later walks whom this one does.
		if err := tx.SetLeafMoved(ctx, a.ID, pending.Kid, res.Moved); err != nil {
			return err
		}
		if err := tx.SetAccountLeafKey(ctx, a.ID, pending.Kid, sealedAcct, string(kp.Algo)); err != nil {
			return err
		}
		if err := tx.SetAccountRoot(ctx, a.ID, vr.RootFingerprint, chain[1]); err != nil {
			return err
		}
		if err := tx.ClearChainSentKids(ctx, a.ID); err != nil {
			return err
		}
		camp := Campaign{AccountID: a.ID, NewKid: pending.Kid, Moved: res.Moved, RequestedAt: pending.CreatedAt}
		held, err := tx.ListContacts(ctx, a.ID)
		if err != nil {
			return err
		}
		for _, c := range held {
			if camp.Owes(c) {
				res.HandshakesDue++
			}
		}
		return nil
	})
	if err != nil {
		return InstallResult{}, err
	}
	res.Retired = retired
	kp.Leaf, kp.Root = chain[0], chain[1]
	// The install replaced the account's copy of its key, and may have deleted or retired a leaf's:
	// their bytes go now, not whenever the pages are reused (store.Store.Scrub).
	if err := m.Store.Scrub(ctx); err != nil {
		res.Warnings = append(res.Warnings, WarnUnscrubbed)
	}
	return res, nil
}

// CertificateInfo is `account certificate`'s answer.
type CertificateInfo struct {
	// Certified is whether the wallet has issued this identity a leaf yet. It was `Protocol`, 1
	// or 2, a generation number that had come to mean exactly this.
	Certified       bool
	RootFingerprint string
	Chain           [][]byte
	Kid             string
	Endpoint        string
	NotBefore       time.Time
	NotAfter        time.Time
	RenewalDue      bool
	PendingCSR      string // the pending request's key id, "" when none
	// HandshakesOwed counts the imported contacts waiting for this identity's next leaf
	// (Manager.HandshakesOwed): a renewal, or a first leaf, is what sends them the handshake.
	HandshakesOwed int
	Superseded     []string
	Former         []string
}

// Served reports whether this host holds a current leaf for the identity. An identity can hold its
// root and none: an import leaves it so until the wallet signs one, and the retire sweep moves a
// current leaf past its notAfter to former (RetireExpiredLeafKeys). Then Kid, Endpoint, NotBefore,
// NotAfter and RenewalDue are zero values, and a door that printed them described a leaf that does
// not exist ("valid until 0001-01-01"). Every door asks this before it gives the leaf's fields.
func (c CertificateInfo) Served() bool { return c.Kid != "" }

// Certificate reports an account's certificate state; renewal is due thirty
// days ahead of the leaf's notAfter (PACT §2).
func (m *Manager) Certificate(ctx context.Context, accountID string, now time.Time) (CertificateInfo, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return CertificateInfo{}, err
	}
	info := CertificateInfo{Certified: a.HasRoot(), RootFingerprint: a.RootFingerprint}
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
	if info.HandshakesOwed, err = m.HandshakesOwed(ctx, accountID); err != nil {
		return CertificateInfo{}, err
	}
	return info, nil
}

// Warning is something a request or an install did not finish although it is made: a code for the
// audit row and a sentence for the person, neither carrying an error's text (building rule 10).
type Warning struct {
	Code string
	Text string
}

// WarnUnscrubbed: a destroyed key's row is gone and its bytes may still be in the store's files,
// because the scrub after it did not finish (store.Store.Scrub); the next leave, retirement,
// install or replaced request scrubs again.
var WarnUnscrubbed = Warning{Code: "unscrubbed", Text: "a destroyed key's bytes may remain in the database's files until the next scrub"}
