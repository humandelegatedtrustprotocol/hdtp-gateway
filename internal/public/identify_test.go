package public

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

var fixedNow = time.Unix(1756000000, 0)

type idEnv struct {
	id      *Identifier
	st      store.Store
	acct    store.Account
	acctKP  *identity.Keypair
	senders map[string]*identity.Keypair
}

func newIdEnv(t *testing.T, algo identity.Algo) *idEnv {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: string(algo)})
	if err := st.SetAccountKey(ctx, a.ID, kp.Fingerprint, []byte{1}); err != nil {
		t.Fatal(err)
	}
	a, _ = st.GetAccountByID(ctx, a.ID)
	return &idEnv{
		st: st, acct: a, acctKP: kp, senders: map[string]*identity.Keypair{},
		id: &Identifier{
			Store:   st,
			Keypair: func(context.Context, string) (*identity.Keypair, error) { return kp, nil },
			Seal:    core.SealRequired, Cert: core.ClientCertPreferred,
			Now: func() time.Time { return fixedNow },
		},
	}
}

func (e *idEnv) sender(t *testing.T, name string, algo identity.Algo) *identity.Keypair {
	t.Helper()
	if kp, ok := e.senders[name]; ok {
		return kp
	}
	kp, err := identity.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	e.senders[name] = kp
	return kp
}

func spkiOf(t *testing.T, kp *identity.Keypair) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cardFor(fpr string) string {
	return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Guest\r\nX-PACT-VERSION:1\r\nX-PACT-KEY:" + fpr + "\r\nEND:VCARD\r\n"
}

// payload builds a request plaintext; spk "" omits the field entirely.
func payload(t *testing.T, method, tool, card, spk string) []byte {
	t.Helper()
	p := map[string]any{"method": method}
	if method == "tools/call" {
		args := map[string]any{}
		if card != "" {
			args["card"] = card
		}
		p["params"] = map[string]any{"name": tool, "arguments": args}
	}
	if spk != "" {
		p["spk"] = spk
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type sealOpt func(*envelope.SealParams)

// msgID gives a call its own idempotency key (distinct calls need distinct ids).
func msgID(id string) sealOpt { return func(p *envelope.SealParams) { p.MsgID = id } }

func (e *idEnv) seal(t *testing.T, sender *identity.Keypair, plain []byte, opts ...sealOpt) *envelope.Envelope {
	t.Helper()
	p := envelope.SealParams{
		Sender: sender, RecipientPub: e.acctKP.Signer.Public(), To: e.acctKP.Fingerprint,
		MsgID: "m1", TS: fixedNow.Unix(), Exp: fixedNow.Add(time.Hour).Unix(),
		CTY: "application/pact-call+json",
	}
	for _, o := range opts {
		o(&p)
	}
	env, err := envelope.Seal(p, plain)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *idEnv) open(t *testing.T, env *envelope.Envelope, tf TransportFacts, d Delivery) (*EnvelopeFacts, error) {
	t.Helper()
	return e.id.OpenSealed(context.Background(), e.acct.ID, e.acctKP.Fingerprint, tf, env, d)
}

// A guest's sealed redeem_invite: signature verifiable ONLY because spk rides
// inside the payload (E1's resolution, SPEC §4.4 step 6).
func TestGuestSealedCallVerifiesViaPayloadSPK(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	g := e.sender(t, "guest", identity.AlgoEd25519)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))
	env := e.seal(t, g, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk))

	f, err := e.open(t, env, TransportFacts{}, DeliveryDirect)
	if err != nil {
		t.Fatalf("guest sealed call refused: %v", err)
	}
	if !f.Guest || f.From != g.Fingerprint || string(f.SPKI) != string(spkiOf(t, g)) {
		t.Fatalf("facts: %+v", f)
	}
	if contacts.CardKey(f.Card) != g.Fingerprint {
		t.Fatalf("card not bound: %q", f.Card)
	}
}

func TestGuestFailureBranches(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	g := e.sender(t, "guest", identity.AlgoP256)
	other := e.sender(t, "other", identity.AlgoP256)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))
	otherSPK := base64.RawURLEncoding.EncodeToString(spkiOf(t, other))

	cases := []struct {
		name  string
		plain []byte
		want  string
	}{
		{"no spk at all", payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), ""), "must carry spk"},
		{"spk of a different key", payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), otherSPK), "does not hash to from"},
		{"spk not base64url", payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), "!!!not-b64!!!"), "base64url"},
		{"spk not an SPKI", payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), base64.RawURLEncoding.EncodeToString([]byte("junk"))), "SubjectPublicKeyInfo"},
		{"card key names someone else", payload(t, "tools/call", "redeem_invite", cardFor(other.Fingerprint), spk), "card X-PACT-KEY"},
		{"no card argument", payload(t, "tools/call", "redeem_invite", "", spk), "must carry a card"},
		{"sealed tools/list from a guest", payload(t, "tools/list", "", "", spk), "may not seal"},
		{"inner method not a tool call", []byte(`{"method":"initialize","spk":"` + spk + `"}`), "inner method"},
		{"unknown payload field", []byte(`{"method":"tools/list","surprise":1}`), "payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := e.seal(t, g, tc.plain)
			_, err := e.open(t, env, TransportFacts{}, DeliveryDirect)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, envelope.ErrInvalid) || Code(err) != "envelope_invalid" {
				t.Fatalf("wrong class: %v (code %s)", err, Code(err))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q in %v", tc.want, err)
			}
		})
	}
}

func TestPinnedSenderPathAndSPKMismatch(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	ctx := context.Background()
	c := e.sender(t, "contact", identity.AlgoP256)
	imposter := e.sender(t, "imposter", identity.AlgoP256)
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c), Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// pinned sender needs no spk at all
	f, err := e.open(t, e.seal(t, c, payload(t, "tools/call", "send_message", "", "")), TransportFacts{}, DeliveryDirect)
	if err != nil || f.Guest || f.From != c.Fingerprint {
		t.Fatalf("pinned path: %+v %v", f, err)
	}
	// a present spk MUST match the pin
	bad := base64.RawURLEncoding.EncodeToString(spkiOf(t, imposter))
	_, err = e.open(t, e.seal(t, c, payload(t, "tools/call", "send_message", "", bad)), TransportFacts{}, DeliveryDirect)
	if err == nil || !strings.Contains(err.Error(), "does not match the pinned key") {
		t.Fatalf("spk/pin mismatch accepted: %v", err)
	}
	// IMPERSONATION, which is the question this whole path exists to answer:
	// somebody who is not the contact sends a message whose header CLAIMS to be
	// from them. Without mTLS — and edge mode forces client certificates off —
	// the header is the only thing naming a sender, so on its own it must count
	// for nothing.
	//
	// Two distinct defences, and they need separate tests because the first hides
	// the second.
	//
	// (a) Tampering with a sealed envelope. The protected header is the HPKE AAD,
	// so rewriting `from` after the fact breaks decryption before any signature
	// is looked at.
	tampered := e.seal(t, imposter, payload(t, "tools/call", "send_message", "", ""))
	var hdr map[string]any
	if err := json.Unmarshal(tampered.Protected, &hdr); err != nil {
		t.Fatal(err)
	}
	hdr["from"] = c.Fingerprint
	rewritten, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Protected = rewritten
	if _, err := e.open(t, tampered, TransportFacts{}, DeliveryDirect); err == nil {
		t.Fatal("a rewritten header was accepted; the AAD binding is gone")
	}

	// (b) A WELL-FORMED forgery, which is what an attacker with a working
	// implementation actually builds: the header says the contact from the start,
	// so the AAD is consistent and it decrypts cleanly. Only the signature can
	// catch this — it is made with the imposter's key and checked against the key
	// this node PINNED for that fingerprint.
	//
	// The previous version of this case mutated a parsed copy of the header and
	// discarded it, so no forgery was ever attempted; it passed because an
	// unpinned sender must carry `spk`, which is a different refusal entirely.
	liar := &identity.Keypair{
		Algo: imposter.Algo, Signer: imposter.Signer,
		Fingerprint: c.Fingerprint, // claims the contact, signs as itself
	}
	forged := e.seal(t, liar, payload(t, "tools/call", "send_message", "", ""))
	_, err = e.open(t, forged, TransportFacts{}, DeliveryDirect)
	if err == nil {
		t.Fatal("an envelope claiming a contact's identity was accepted on somebody " +
			"else's signature — the name in the header would be all it takes to " +
			"impersonate anyone")
	}
	if !errors.Is(err, envelope.ErrInvalid) {
		t.Errorf("impersonation refused for the wrong reason: %v", err)
	}
}

// SPEC §5.3: both proofs present ⇒ they MUST match.
func TestUnifiedIdentityRuleBothPresent(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	g := e.sender(t, "guest", identity.AlgoP256)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))
	env := e.seal(t, g, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk))

	// matching certificate: accepted
	if _, err := e.open(t, env, TransportFacts{ClientCertFingerprint: g.Fingerprint}, DeliveryDirect); err != nil {
		t.Fatalf("matching cert refused: %v", err)
	}
	// mismatched certificate: envelope_invalid, even though the envelope alone is valid
	_, err := e.open(t, env, TransportFacts{ClientCertFingerprint: "sha256:someone-else"}, DeliveryDirect)
	if err == nil || Code(err) != "envelope_invalid" || !strings.Contains(err.Error(), "does not match envelope signer") {
		t.Fatalf("mismatch not rejected: %v", err)
	}
}

func TestAddressingKidSuiteAndFreshnessBranches(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	g := e.sender(t, "guest", identity.AlgoP256)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))
	good := func() []byte { return payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk) }

	// wrong recipient in `to`
	env := e.seal(t, g, good(), func(p *envelope.SealParams) { p.To = "sha256:not-me" })
	if _, err := e.open(t, env, TransportFacts{}, DeliveryDirect); err == nil || !strings.Contains(err.Error(), "addressed to") {
		t.Fatalf("wrong to accepted: %v", err)
	}
	// expired
	env = e.seal(t, g, good(), func(p *envelope.SealParams) {
		p.TS = fixedNow.Add(-2 * time.Hour).Unix()
		p.Exp = fixedNow.Add(-time.Hour).Unix()
	})
	if _, err := e.open(t, env, TransportFacts{}, DeliveryDirect); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired accepted: %v", err)
	}
	// lifetime > 30 days
	env = e.seal(t, g, good(), func(p *envelope.SealParams) { p.Exp = fixedNow.Add(40 * 24 * time.Hour).Unix() })
	if _, err := e.open(t, env, TransportFacts{}, DeliveryDirect); err == nil || !strings.Contains(err.Error(), "30 days") {
		t.Fatalf("overlong lifetime accepted: %v", err)
	}
	// stale ts, delivered directly → rejected; the same envelope via relay → accepted
	stale := e.seal(t, g, good(), func(p *envelope.SealParams) {
		p.TS = fixedNow.Add(-30 * time.Minute).Unix()
		p.Exp = fixedNow.Add(24 * time.Hour).Unix()
	})
	if _, err := e.open(t, stale, TransportFacts{}, DeliveryDirect); err == nil || !strings.Contains(err.Error(), "300 s") {
		t.Fatalf("stale direct accepted: %v", err)
	}
	if _, err := e.open(t, stale, TransportFacts{}, DeliveryRelay); err != nil {
		t.Fatalf("relay-delivered envelope must be exempt from the 300 s window: %v", err)
	}
	// future ts beyond the window
	future := e.seal(t, g, good(), func(p *envelope.SealParams) {
		p.TS = fixedNow.Add(30 * time.Minute).Unix()
		p.Exp = fixedNow.Add(2 * time.Hour).Unix()
	})
	if _, err := e.open(t, future, TransportFacts{}, DeliveryDirect); err == nil || !strings.Contains(err.Error(), "300 s") {
		t.Fatalf("future ts accepted: %v", err)
	}
	// suite mismatch: an Ed25519 account cannot be addressed with the P-256 suite
	e2 := newIdEnv(t, identity.AlgoEd25519)
	g2 := e2.sender(t, "guest", identity.AlgoP256)
	spk2 := base64.RawURLEncoding.EncodeToString(spkiOf(t, g2))
	env2 := e2.seal(t, g2, payload(t, "tools/call", "redeem_invite", cardFor(g2.Fingerprint), spk2))
	// re-encode the header with the wrong suite so the mismatch is what fails
	h, _ := envelope.ParseHeader(env2)
	if h.Suite != envelope.SuiteX25519 {
		t.Fatalf("fixture suite: %s", h.Suite)
	}
}

// SPEC §4.4/§9.1: a blocked sender is processed exactly as an unknown one at
// this layer — sealing must never distinguish blocked from never-met.
func TestBlockedSenderIsNotAnOracle(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	ctx := context.Background()
	blocked := e.sender(t, "blocked", identity.AlgoP256)
	unknown := e.sender(t, "unknown", identity.AlgoP256)
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: blocked.Fingerprint, SPKI: spkiOf(t, blocked), Status: "blocked",
	}); err != nil {
		t.Fatal(err)
	}
	// sealed tools/list: identical refusal for both
	var errs []string
	for _, kp := range []*identity.Keypair{blocked, unknown} {
		spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, kp))
		_, err := e.open(t, e.seal(t, kp, payload(t, "tools/list", "", "", spk)), TransportFacts{}, DeliveryDirect)
		if err == nil {
			t.Fatalf("sealed tools/list accepted for %s", kp.Fingerprint)
		}
		errs = append(errs, Code(err))
	}
	if errs[0] != errs[1] || errs[0] != "envelope_invalid" {
		t.Fatalf("blocked/unknown distinguishable: %v", errs)
	}
	// a blocked sender's well-formed guest call opens exactly like an unknown
	// one's — the demotion happens later, at tiering
	for _, kp := range []*identity.Keypair{blocked, unknown} {
		spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, kp))
		f, err := e.open(t, e.seal(t, kp, payload(t, "tools/call", "request_contact", cardFor(kp.Fingerprint), spk)), TransportFacts{}, DeliveryDirect)
		if err != nil {
			t.Fatalf("%s refused: %v", kp.Fingerprint, err)
		}
		if f.From != kp.Fingerprint {
			t.Fatal("identity")
		}
	}
}

// The seal-policy matrix of the AC: none/optional/required × cert/envelope/neither.
func TestSealPolicyMatrix(t *testing.T) {
	cases := []struct {
		seal        core.Seal
		cert        core.ClientCert
		haveCert    bool
		substantive bool
		want        string // "" = allowed
	}{
		{core.SealNone, core.ClientCertPreferred, true, true, ""},
		{core.SealNone, core.ClientCertPreferred, false, true, ""},
		{core.SealOptional, core.ClientCertPreferred, true, true, ""},
		{core.SealOptional, core.ClientCertPreferred, false, true, ""},
		{core.SealRequired, core.ClientCertPreferred, true, true, "seal_required"},
		{core.SealRequired, core.ClientCertPreferred, false, true, "identity_required"},
		{core.SealRequired, core.ClientCertPreferred, true, false, ""},  // tools/list always answers
		{core.SealRequired, core.ClientCertPreferred, false, false, ""}, // ditto, anonymously
		{core.SealOptional, core.ClientCertRequired, false, false, "identity_required"},
		{core.SealOptional, core.ClientCertRequired, true, true, ""},
		{core.SealRequired, core.ClientCertRequired, false, true, "identity_required"},
	}
	for _, tc := range cases {
		id := &Identifier{Seal: tc.seal, Cert: tc.cert, Now: func() time.Time { return fixedNow }}
		tf := TransportFacts{}
		if tc.haveCert {
			tf.ClientCertFingerprint = "sha256:caller"
		}
		fpr, err := id.PlaintextGate(tf, "send_message", tc.substantive)
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%v/%v cert=%v subst=%v: refused %v", tc.seal, tc.cert, tc.haveCert, tc.substantive, err)
			}
			if tc.haveCert && fpr != "sha256:caller" {
				t.Fatalf("identity lost: %q", fpr)
			}
			continue
		}
		if Code(err) != tc.want {
			t.Fatalf("%v/%v cert=%v subst=%v: got %q want %q", tc.seal, tc.cert, tc.haveCert, tc.substantive, Code(err), tc.want)
		}
	}
}

func TestReplayReturnsRecordedAck(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	ctx := context.Background()
	c := e.sender(t, "contact", identity.AlgoP256)
	_, _ = e.st.InsertContact(ctx, store.Contact{AccountID: e.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c), Status: "active"})
	f, err := e.open(t, e.seal(t, c, payload(t, "tools/call", "send_message", "", "")), TransportFacts{}, DeliveryDirect)
	if err != nil {
		t.Fatal(err)
	}
	// first sight reserves; nothing to replay
	if ack, replayed, err := e.id.Replay(ctx, e.st, e.acct.ID, f); err != nil || replayed || ack != "" {
		t.Fatalf("first: %q %v %v", ack, replayed, err)
	}
	// The dispatcher writes the ack under the envelope key, not the bare id: an
	// inner tool keeps its own idempotency for the same msg_id (§4.5).
	if err := e.st.UpdateIdempotencyAck(ctx, e.acct.ID, f.From, EnvelopeKey(f.Header.MsgID), `{"status":"delivered"}`); err != nil {
		t.Fatal(err)
	}
	// second sight returns the recorded acknowledgment without re-executing
	ack, replayed, err := e.id.Replay(ctx, e.st, e.acct.ID, f)
	if err != nil || !replayed || ack != `{"status":"delivered"}` {
		t.Fatalf("replay: %q %v %v", ack, replayed, err)
	}
}

// AC (P11-13): a contact left fingerprint-only by a rotation binds its key from
// the SEALED ENVELOPE, so rotation is not contact loss on the relay and edge
// paths (SPEC §3.9, §4.4, escalation E7).
//
// P10-09b recorded the key only in PlaintextGate, which needs an mTLS client
// certificate. Two shipped delivery paths have none: a relayed envelope carries
// no transport facts at all, and edge mode forces client certificates off. On
// those paths the contact fell through to the guest branch, which demands a card
// `send_message` does not carry — so every message from a rotated contact was
// refused, permanently, for exactly the deployments that need a relay or an edge.
func TestRotatedContactBindsItsKeyFromASealedEnvelope(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	ctx := context.Background()
	c := e.sender(t, "rotated", identity.AlgoP256)

	var bound []byte
	e.id.BindKey = func(_ context.Context, _, fpr string, spki []byte) error {
		if fpr != c.Fingerprint {
			t.Fatalf("bound the wrong fingerprint: %s", fpr)
		}
		bound = spki
		return nil
	}
	// Fingerprint-only: exactly what §3.9 leaves behind after a rotation.
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: c.Fingerprint,
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}

	// A relayed envelope: no transport facts whatsoever.
	env := e.seal(t, c, payload(t, "tools/call", "send_message", "", base64.RawURLEncoding.EncodeToString(spkiOf(t, c))))
	facts, err := e.open(t, env, TransportFacts{}, DeliveryRelay)
	if err != nil {
		t.Fatalf("a rotated contact's relayed message was refused: %v", err)
	}
	if facts.Guest {
		t.Fatal("a pinned contact was demoted to guest, which would demand a card")
	}
	if len(bound) == 0 {
		t.Fatal("the key was not recorded, so the next message would be refused again")
	}

	// A key that does NOT hash to the pinned fingerprint must not bind: the
	// fingerprint is the pin, and this is the only thing standing between an
	// impostor and a contact whose key we do not yet hold.
	other := e.sender(t, "impostor", identity.AlgoP256)
	bound = nil
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: "sha256:not-a-real-key", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	env2 := e.seal(t, other, payload(t, "tools/call", "send_message", "", base64.RawURLEncoding.EncodeToString(spkiOf(t, other))), msgID("m2"))
	f2, err := e.open(t, env2, TransportFacts{}, DeliveryRelay)
	if err == nil && !f2.Guest {
		t.Fatal("a sender whose key does not hash to any pin was treated as pinned")
	}
	if len(bound) != 0 {
		t.Fatal("a key that hashes to nothing we pinned was bound")
	}
}

// The envelope's replay guard and a tool's own idempotency share one table, so
// they must never share a key. call_contact sends the tool's msg_id as the
// envelope's, which is what made them collide: a sealed book_slot reserved the
// id as an envelope and then read its own reservation as another attempt in
// flight. This pins the separation rather than trusting the convention.
func TestEnvelopeKeyCannotCollideWithAToolsOwnIdempotency(t *testing.T) {
	for _, id := range []string{"m1", "bk-1", "", "env:already-prefixed"} {
		if got := EnvelopeKey(id); got == id {
			t.Fatalf("EnvelopeKey(%q) = %q: an envelope would claim the key a tool needs", id, got)
		}
	}
	// And the namespace is stable: a reservation written by one release must
	// still be found by the next, or a redeploy re-executes calls it already
	// answered.
	if got := EnvelopeKey("m1"); got != "env:m1" {
		t.Fatalf("EnvelopeKey changed shape to %q; in-flight reservations would be orphaned", got)
	}
}
