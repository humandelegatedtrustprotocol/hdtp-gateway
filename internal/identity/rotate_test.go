package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

type rotAudit struct{ rows []string }

func (a *rotAudit) fn(action, resource, outcome string) {
	a.rows = append(a.rows, action+" "+resource+" "+outcome)
}
func (a *rotAudit) has(sub string) bool {
	for _, r := range a.rows {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func node(t *testing.T, slug string) (*Manager, store.Store, store.Account) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), slug+".db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: kr}
	a, err := m.CreateAccount(context.Background(), slug, strings.ToUpper(slug), AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	return m, st, a
}

// Two in-process nodes: Alice rotates; Bob (her contact) receives update_contact
// through the fan-out seam and re-pins; grace and expiry behave per SPEC §3.9.
func TestRotationPropagatesGraceAndExpiry(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1756000000, 0)
	mA, stA, alice := node(t, "alice")
	_, stB, bob := node(t, "bob")
	aud := &rotAudit{}
	rot := &Rotator{Manager: mA, Audit: aud.fn, Now: func() time.Time { return clock }}

	// Bob pins Alice's ORIGINAL key (full SPKI, as redemption does)
	kpA0, _, err := rot.ActiveKeypairs(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	spkiA0, _ := x509.MarshalPKIXPublicKey(kpA0.Signer.Public())
	if _, err := stB.InsertContact(ctx, store.Contact{AccountID: bob.ID, Fingerprint: kpA0.Fingerprint, SPKI: spkiA0, Status: "active", Card: "old"}); err != nil {
		t.Fatal(err)
	}
	// Alice lists Bob as an active contact (so fan-out reaches him)
	if _, err := stA.InsertContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: "sha256:bob", SPKI: []byte{1}, Status: "active"}); err != nil {
		t.Fatal(err)
	}

	r, err := rot.Rotate(ctx, alice.ID, 0)
	if err != nil || r.OldFpr != kpA0.Fingerprint || r.NewFpr == r.OldFpr || len(r.Proof) == 0 {
		t.Fatalf("rotate: %+v %v", r, err)
	}
	if r.GraceUntil.Sub(clock) != DefaultGrace {
		t.Fatalf("grace default: %v", r.GraceUntil.Sub(clock))
	}
	acct, _ := stA.GetAccountByID(ctx, alice.ID)
	if acct.Fingerprint != r.NewFpr {
		t.Fatal("account not re-keyed")
	}
	// a second rotation inside the grace window is refused
	if _, err := rot.Rotate(ctx, alice.ID, 0); err == nil {
		t.Fatal("overlapping rotation accepted")
	}

	// the fan-out delivers update_contact to Bob's node, which verifies the
	// OLD key's signature over the NEW fingerprint and re-pins
	newCard := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:ALICE\r\nX-PACT-VERSION:1\r\nX-PACT-KEY:" + r.NewFpr + "\r\nEND:VCARD\r\n"
	bobSide := bobReceiver(t, stB, bob.ID)
	done, failed, err := rot.Fanout(ctx, r, newCard, func(ctx context.Context, c store.Contact, card string, proof []byte) error {
		return bobSide(kpA0.Fingerprint, card, proof)
	})
	if err != nil || done != 1 || failed != 0 {
		t.Fatalf("fanout: done=%d failed=%d err=%v", done, failed, err)
	}
	if _, err := stB.GetContact(ctx, bob.ID, r.NewFpr); err != nil {
		t.Fatalf("bob did not re-pin: %v", err)
	}
	if _, err := stB.GetContact(ctx, bob.ID, kpA0.Fingerprint); err == nil {
		t.Fatal("bob still pins the old key")
	}
	// The account: prefix carries the ID (the audit sink recovers the column
	// from it); the slug and both fingerprints ride alongside as facts.
	if !aud.has("account_rotate account:" + alice.ID + " slug:alice old:" + kpA0.Fingerprint + " new:" + r.NewFpr + " ok") {
		t.Fatalf("rotation not audited: %v", aud.rows)
	}

	// grace: BOTH keys live — a straggler sealing to the old key still reaches Alice
	cur, prev, err := rot.ActiveKeypairs(ctx, alice.ID)
	if err != nil || cur.Fingerprint != r.NewFpr || prev == nil || prev.Fingerprint != kpA0.Fingerprint {
		t.Fatalf("active keys during grace: cur=%v prev=%v err=%v", cur, prev, err)
	}
	if expired, _ := rot.ExpireGrace(ctx, alice.ID); expired {
		t.Fatal("grace expired early")
	}
	// post-grace: the old key is destroyed and no longer usable
	clock = clock.Add(DefaultGrace + time.Hour)
	if expired, err := rot.ExpireGrace(ctx, alice.ID); err != nil || !expired {
		t.Fatalf("expire: %v %v", expired, err)
	}
	cur, prev, _ = rot.ActiveKeypairs(ctx, alice.ID)
	if cur.Fingerprint != r.NewFpr || prev != nil {
		t.Fatal("old key survived the grace period")
	}
	if _, sealed, _, _ := stA.GetAccountPrevKey(ctx, alice.ID); len(sealed) != 0 {
		t.Fatal("old private key material not destroyed")
	}
	// grace cap
	r2, err := rot.Rotate(ctx, alice.ID, 400*24*time.Hour)
	if err != nil || r2.GraceUntil.Sub(clock) != MaxGrace {
		t.Fatalf("grace cap: %v %v", r2.GraceUntil.Sub(clock), err)
	}
}

// bobReceiver stands in for Bob's node handling update_contact: verify the
// old-key signature against the pinned key and re-pin (contacts.Manager does
// exactly this in production; the identity package cannot import contacts).
func bobReceiver(t *testing.T, st store.Store, accountID string) func(oldFpr, newCard string, proof []byte) error {
	t.Helper()
	return func(oldFpr, newCard string, proof []byte) error {
		ctx := context.Background()
		c, err := st.GetContact(ctx, accountID, oldFpr)
		if err != nil {
			return err
		}
		newFpr := ""
		for _, line := range strings.Split(newCard, "\r\n") {
			if strings.HasPrefix(line, "X-PACT-KEY:") {
				newFpr = strings.TrimPrefix(line, "X-PACT-KEY:")
			}
		}
		pub, err := x509.ParsePKIXPublicKey(c.SPKI)
		if err != nil {
			return err
		}
		if !VerifyBytes(pub, []byte(newFpr), proof) {
			return errors.New("rotation signature invalid")
		}
		return st.RepinContact(ctx, accountID, oldFpr, newFpr, nil, newCard, time.Now().Unix())
	}
}

func TestInterruptedFanoutResumes(t *testing.T) {
	ctx := context.Background()
	mA, stA, alice := node(t, "alice")
	rot := &Rotator{Manager: mA}
	for _, f := range []string{"sha256:c1", "sha256:c2", "sha256:c3"} {
		_, _ = stA.InsertContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: f, SPKI: []byte{1}, Status: "active"})
	}
	_, _ = stA.InsertContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: "sha256:blocked", SPKI: []byte{1}, Status: "blocked"})
	r, err := rot.Rotate(ctx, alice.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	flaky := func(ctx context.Context, c store.Contact, card string, proof []byte) error {
		calls[c.Fingerprint]++
		if c.Fingerprint == "sha256:c2" && calls[c.Fingerprint] == 1 {
			return errors.New("peer unreachable")
		}
		return nil
	}
	done, failed, err := rot.Fanout(ctx, r, "card", flaky)
	if err == nil || done != 2 || failed != 1 {
		t.Fatalf("first pass: done=%d failed=%d err=%v", done, failed, err)
	}
	rows, _ := stA.ListRotationFanout(ctx, alice.ID)
	pending := 0
	for _, row := range rows {
		if row.Status == "pending" && row.ContactFpr == "sha256:c2" && row.Attempts == 1 && row.LastError == "peer unreachable" {
			pending++
		}
	}
	if pending != 1 || len(rows) != 3 {
		t.Fatalf("progress rows: %+v", rows)
	}
	// resume: only the pending contact is retried; done ones are not re-called
	done, failed, err = rot.Fanout(ctx, r, "card", flaky)
	if err != nil || done != 3 || failed != 0 {
		t.Fatalf("resume: done=%d failed=%d err=%v", done, failed, err)
	}
	if calls["sha256:c1"] != 1 || calls["sha256:c3"] != 1 || calls["sha256:c2"] != 2 || calls["sha256:blocked"] != 0 {
		t.Fatalf("calls: %v", calls)
	}
}

// AC (P14-10a): an interrupted fan-out must be resumable.
//
// Rotate refuses a second rotation inside a grace period, which is right —
// rotating twice would invalidate the key the first one just published. But the
// CLI told the owner to "re-run rotate-key to resume the fan-out" and re-running
// hit exactly that refusal, so a contact missed by the first attempt stayed
// missed and was lost when the old key expired (SPEC §3.9 step 5).
func TestInFlightReturnsTheRotationBeingResumed(t *testing.T) {
	ctx := context.Background()
	mA, _, alice := node(t, "alice")
	rot := &Rotator{Manager: mA}

	// Nothing in flight before a rotation.
	if _, ok, err := rot.InFlight(ctx, alice.ID); err != nil || ok {
		t.Fatalf("InFlight reported a rotation before any happened: ok=%v err=%v", ok, err)
	}

	first, err := rot.Rotate(ctx, alice.ID, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Rotating again must still be refused.
	if _, err := rot.Rotate(ctx, alice.ID, 48*time.Hour); err == nil {
		t.Fatal("a second rotation inside the grace period was allowed; it would invalidate " +
			"the key the first one just published")
	}

	// But the in-flight rotation is available to resume, with the same identities.
	got, ok, err := rot.InFlight(ctx, alice.ID)
	if err != nil || !ok {
		t.Fatalf("InFlight did not offer the rotation to resume: ok=%v err=%v", ok, err)
	}
	if got.NewFpr != first.NewFpr {
		t.Errorf("resume targets %s, the rotation published %s — a resume must finish the "+
			"SAME rotation, not start another", got.NewFpr, first.NewFpr)
	}
	if got.OldFpr != first.OldFpr {
		t.Errorf("resume signs with %s, the rotation used %s", got.OldFpr, first.OldFpr)
	}
	if len(got.Proof) == 0 {
		t.Error("the resumed rotation carries no proof, so update_contact would be refused")
	}
	// Compared in whole seconds: the deadline is persisted as a Unix second, so a
	// reconstructed rotation cannot carry the original's sub-second part. What
	// must not move is the deadline itself — extending it would quietly give the
	// old key longer to live than the owner chose.
	if got.GraceUntil.Unix() != first.GraceUntil.Unix() {
		t.Errorf("resume moved the deadline: %s vs %s", got.GraceUntil, first.GraceUntil)
	}
}

// GraceImmediate: the old key must still work for the fan-out — it is the only
// key the contacts trust — and be gone the moment RetireNow runs. A plain 0
// must keep meaning the default, because 0 is what an omitted duration parses
// to, and "I forgot the flag" must never become "destroy the old key now".
func TestImmediateRotationKeepsTheOldKeyOnlyForTheFanout(t *testing.T) {
	ctx := context.Background()
	m, _, a := node(t, "alice")
	clock := time.Unix(1_800_000_000, 0)
	rot := &Rotator{Manager: m, Now: func() time.Time { return clock }}

	r, err := rot.Rotate(ctx, a.ID, GraceImmediate)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Immediate || r.GraceUntil.Sub(clock) != ImmediateWindow {
		t.Fatalf("immediate rotation got Immediate=%v window=%v", r.Immediate, r.GraceUntil.Sub(clock))
	}
	if _, prev, err := rot.ActiveKeypairs(ctx, a.ID); err != nil || prev == nil || prev.Fingerprint != r.OldFpr {
		t.Fatalf("the retiring key must remain usable for the fan-out: prev=%v err=%v", prev, err)
	}
	if err := rot.RetireNow(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, prev, _ := rot.ActiveKeypairs(ctx, a.ID); prev != nil {
		t.Fatal("RetireNow left the old key usable")
	}
	if _, resuming, _ := rot.InFlight(ctx, a.ID); resuming {
		t.Fatal("nothing should be resumable after an immediate retirement")
	}
	// And a plain zero is still the default, not a cutover.
	clock = clock.Add(time.Hour)
	r2, err := rot.Rotate(ctx, a.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Immediate || r2.GraceUntil.Sub(clock) != DefaultGrace {
		t.Fatalf("an unspecified grace must stay the default: Immediate=%v window=%v", r2.Immediate, r2.GraceUntil.Sub(clock))
	}
}
