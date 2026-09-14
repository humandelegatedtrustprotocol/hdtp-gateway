package identity

// Key rotation (SPEC §3.9, PACT §2): a new keypair is minted and sealed
// alongside the old one; the account's card is re-derived; every active
// contact's update_contact is called with the new card plus the OLD key's
// signature over the NEW fingerprint; per-contact completion is durable so an
// interrupted fan-out resumes. During the grace period both keys stay live —
// the old one for callers that have not re-pinned, selected by the envelope
// kid or presented as the client certificate. At grace end the old private
// key is destroyed, regardless of stragglers (lost key = new identity).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

const (
	// DefaultGrace / MaxGrace per SPEC §3.9.
	DefaultGrace = 14 * 24 * time.Hour
	MaxGrace     = 90 * 24 * time.Hour
	// GraceImmediate asks for no grace period at all: the old key lives only long
	// enough to announce the new one, then RetireNow destroys it. It is a distinct
	// sentinel rather than 0 because 0 is what an OMITTED duration parses to, and
	// an omitted grace must keep meaning the default — never an immediate cutover.
	GraceImmediate time.Duration = -1
	// ImmediateWindow bounds how long the retiring key stays usable for the
	// fan-out under GraceImmediate. Contacts not told inside it are lost.
	ImmediateWindow = 15 * time.Minute
)

// Rotation is the outcome of Rotate: what fan-out needs.
type Rotation struct {
	AccountID  string
	OldFpr     string
	NewFpr     string
	Proof      []byte // old-key signature over the new fingerprint (PACT §2)
	GraceUntil time.Time
	// Immediate: the caller asked for GraceImmediate and must RetireNow once the
	// fan-out is done; GraceUntil is only the fan-out allowance.
	Immediate bool
	// LegacyOnly restricts the fan-out to contacts pinned as 1.x. A 2.0 leaf
	// install with a fresh key is a 1.x rotation toward them (PACT Appendix C
	// row 2) and nothing toward 2.0 contacts, who learn the leaf from the chain.
	LegacyOnly bool
}

// Rotator performs rotations for a node's accounts.
type Rotator struct {
	Manager *Manager
	Audit   func(action, resource, outcome string)
	Now     func() time.Time
}

func (r *Rotator) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Rotator) audit(action, resource, outcome string) {
	if r.Audit != nil {
		r.Audit(action, resource, outcome)
	}
}

// Rotate mints and installs the new key, keeping the old one live until
// graceUntil (default 14 d, capped at 90 d). A rotation while a previous grace
// window is still open is refused: one retiring key at a time.
func (r *Rotator) Rotate(ctx context.Context, accountID string, grace time.Duration) (Rotation, error) {
	st := r.Manager.Store
	immediate := grace == GraceImmediate
	if immediate {
		grace = ImmediateWindow
	} else if grace <= 0 {
		grace = DefaultGrace
	}
	if grace > MaxGrace {
		grace = MaxGrace
	}
	if prevFpr, _, until, err := st.GetAccountPrevKey(ctx, accountID); err == nil && prevFpr != "" && until > r.now().Unix() {
		return Rotation{}, fmt.Errorf("identity: a rotation is still in its grace period (until %s)", time.Unix(until, 0).UTC().Format(time.RFC3339))
	}
	a, err := st.GetAccountByID(ctx, accountID)
	if err != nil {
		return Rotation{}, err
	}
	sealedOld, err := st.GetAccountSealedKey(ctx, accountID)
	if err != nil {
		return Rotation{}, err
	}
	oldKP, err := r.Manager.LoadKeypair(sealedOld)
	if err != nil {
		return Rotation{}, err
	}
	newKP, err := Generate(Algo(a.Algo))
	if err != nil {
		return Rotation{}, err
	}
	der, err := MarshalPKCS8(newKP)
	if err != nil {
		return Rotation{}, err
	}
	sealedNew, err := r.Manager.Keyring.Encrypt(der, []byte(keyAAD))
	if err != nil {
		return Rotation{}, err
	}
	proof, err := signBytes(oldKP, []byte(newKP.Fingerprint))
	if err != nil {
		return Rotation{}, err
	}
	until := r.now().Add(grace)
	if err := st.RotateAccountKey(ctx, accountID, newKP.Fingerprint, sealedNew, until.Unix()); err != nil {
		r.audit("account_rotate", "account:"+a.ID+" slug:"+a.Slug, "error")
		return Rotation{}, err
	}
	// The account: prefix must carry the ID — the sink recovers the account
	// column from it, and a slug there scopes the row to an account that does
	// not exist, hiding a successful rotation from every scoped read.
	r.audit("account_rotate",
		"account:"+a.ID+" slug:"+a.Slug+" old:"+oldKP.Fingerprint+" new:"+newKP.Fingerprint, "ok")
	return Rotation{AccountID: accountID, OldFpr: oldKP.Fingerprint, NewFpr: newKP.Fingerprint, Proof: proof, GraceUntil: until, Immediate: immediate}, nil
}

// RetireNow destroys the retiring key without waiting for its grace period —
// the second half of GraceImmediate, run once the fan-out has been attempted.
// Any contact not told by then is lost: there is no key left to reach them
// with, and re-pairing is the only way back (lost key = new identity).
func (r *Rotator) RetireNow(ctx context.Context, accountID string) error {
	st := r.Manager.Store
	prevFpr, _, _, err := st.GetAccountPrevKey(ctx, accountID)
	if err != nil || prevFpr == "" {
		return err
	}
	if err := st.ClearAccountPrevKey(ctx, accountID); err != nil {
		return err
	}
	r.audit("account_rotate_retire", "account:"+accountID+" prev:"+prevFpr, "ok")
	return nil
}

// ActiveKeypairs returns the current key and, while the grace period is open,
// the retiring one (nil otherwise) — inbound envelopes pick by kid, outbound
// calls to un-repinned contacts present the old certificate.
// InFlight rebuilds the rotation currently inside its grace period, so an
// interrupted fan-out can be RESUMED without rotating again.
//
// Rotating twice inside one grace period would invalidate the key the first
// rotation had just published, so Rotate refuses it — correctly. But the refusal
// left no way to finish the job, while the CLI told the owner to "re-run
// rotate-key to resume the fan-out". A contact that never received
// `update_contact` is lost when the old key is destroyed at grace expiry
// (§3.9 step 5), so "no way to retry" is the expensive half of that.
//
// The proof is re-signed rather than stored: it is a signature by the OLD key
// over the NEW fingerprint, and both keys are still in the keyring during grace.
func (r *Rotator) InFlight(ctx context.Context, accountID string) (Rotation, bool, error) {
	st := r.Manager.Store
	prevFpr, _, until, err := st.GetAccountPrevKey(ctx, accountID)
	if err != nil || prevFpr == "" || until <= r.now().Unix() {
		return Rotation{}, false, nil
	}
	newKP, oldKP, err := r.ActiveKeypairs(ctx, accountID)
	if err != nil {
		return Rotation{}, false, err
	}
	if newKP == nil || oldKP == nil {
		return Rotation{}, false, fmt.Errorf("identity: rotation in grace but a keypair is missing")
	}
	proof, err := signBytes(oldKP, []byte(newKP.Fingerprint))
	if err != nil {
		return Rotation{}, false, err
	}
	return Rotation{
		AccountID: accountID, OldFpr: oldKP.Fingerprint, NewFpr: newKP.Fingerprint,
		Proof: proof, GraceUntil: time.Unix(until, 0),
	}, true, nil
}

func (r *Rotator) ActiveKeypairs(ctx context.Context, accountID string) (current, previous *Keypair, err error) {
	st := r.Manager.Store
	sealed, err := st.GetAccountSealedKey(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	if current, err = r.Manager.LoadKeypair(sealed); err != nil {
		return nil, nil, err
	}
	prevFpr, prevSealed, until, err := st.GetAccountPrevKey(ctx, accountID)
	if err != nil || prevFpr == "" || until <= r.now().Unix() {
		return current, nil, nil
	}
	previous, err = r.Manager.LoadKeypair(prevSealed)
	if err != nil {
		return current, nil, err
	}
	return current, previous, nil
}

// ExpireGrace destroys the retiring key once its grace period has ended
// (SPEC §3.9 step 5). Returns true when a key was destroyed.
func (r *Rotator) ExpireGrace(ctx context.Context, accountID string) (bool, error) {
	st := r.Manager.Store
	prevFpr, _, until, err := st.GetAccountPrevKey(ctx, accountID)
	if err != nil || prevFpr == "" {
		return false, err
	}
	if until > r.now().Unix() {
		return false, nil
	}
	if err := st.ClearAccountPrevKey(ctx, accountID); err != nil {
		return false, err
	}
	r.audit("account_rotate_expire", "account:"+accountID+" prev:"+prevFpr, "ok")
	return true, nil
}

// FanoutCall delivers one update_contact to one contact (the outbound client,
// presenting the OLD certificate — that is the identity the peer still pins).
type FanoutCall func(ctx context.Context, contact store.Contact, newCard string, proof []byte) error

// Fanout walks the account's active contacts, recording per-contact outcome
// durably; contacts already marked done for this rotation are skipped, so a
// re-run after an interruption resumes exactly where it stopped.
func (r *Rotator) Fanout(ctx context.Context, rot Rotation, newCard string, call FanoutCall) (done, failed int, err error) {
	st := r.Manager.Store
	contacts, err := st.ListContacts(ctx, rot.AccountID)
	if err != nil {
		return 0, 0, err
	}
	progress := map[string]store.RotationFanout{}
	if rows, err := st.ListRotationFanout(ctx, rot.AccountID); err == nil {
		for _, row := range rows {
			progress[row.ContactFpr] = row
		}
	}
	for _, c := range contacts {
		if c.Status != "active" || (rot.LegacyOnly && c.Protocol == 2) {
			continue
		}
		if p, ok := progress[c.Fingerprint]; ok && p.NewFpr == rot.NewFpr && p.Status == "done" {
			done++
			continue
		}
		attempts := progress[c.Fingerprint].Attempts + 1
		callErr := call(ctx, c, newCard, rot.Proof)
		status, lastErr := "done", ""
		if callErr != nil {
			status, lastErr = "pending", callErr.Error()
			failed++
		} else {
			done++
		}
		_ = st.UpsertRotationFanout(ctx, store.RotationFanout{
			AccountID: rot.AccountID, ContactFpr: c.Fingerprint, NewFpr: rot.NewFpr,
			Status: status, Attempts: attempts, LastError: lastErr, UpdatedAt: r.now().Unix(),
		})
		r.audit("account_rotate_fanout", "account:"+rot.AccountID+" contact:"+c.Fingerprint, status)
	}
	if failed > 0 {
		return done, failed, errors.New("identity: rotation fan-out incomplete; re-run to resume")
	}
	return done, failed, nil
}
