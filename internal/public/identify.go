package public

// The envelope validation pipeline (SPEC §4.4) and the unified caller-identity
// rule (§5.3), as code. This is the ONE place a caller's identity is decided:
// every sealed call passes the numbered open order, every call — sealed or not
// — passes the seal/client-cert policy gate, and the result is either a
// resolved identity or one of the three PACT §12 codes.
//
// Order matters and is spec-pinned: decode → suite → to → kid → OPEN →
// verify signature → freshness → idempotency → dispatch. Opening precedes
// verification because HPKE Base needs no sender key, which is exactly what
// lets an unpinned sender's key (`spk`) ride inside the ciphertext (§4.4 step 6).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// The policy errors of §4.11; envelope failures use envelope.ErrInvalid
// (`envelope_invalid`). ErrSealNotAccepted is 1.2's refusal of an envelope
// sent to a recipient whose policy is none (PACT §13.4: sealed_call absent;
// senders MUST NOT seal).
var (
	ErrSealRequired     = errors.New("seal_required")
	ErrIdentityRequired = errors.New("identity_required")
	ErrSealNotAccepted  = errors.New("seal_not_accepted")
	// ErrPendingApproval is PACT §5.3 on the transport path: a pinned root
	// calling from an address the owner has not yet approved. ErrPendingStatus
	// is the one call that address is allowed — the update_contact that brought
	// it — answered `{"status":"pending"}` rather than an error.
	ErrPendingApproval = errors.New("pending_approval")
	ErrPendingStatus   = errors.New("pending")
)

// Code maps an error to its PACT §12 wire code ("" when it is not one of ours).
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrSealRequired):
		return "seal_required"
	case errors.Is(err, ErrIdentityRequired):
		return "identity_required"
	case errors.Is(err, ErrSealNotAccepted):
		return "seal_not_accepted"
	case errors.Is(err, ErrPendingApproval):
		return "pending_approval"
	case errors.Is(err, ErrChainRequired):
		return "chain_required"
	case errors.As(err, new(*CertificateRenewed)):
		return "certificate_renewed"
	case errors.Is(err, envelope.ErrInvalid):
		return "envelope_invalid"
	default:
		return "unavailable"
	}
}

// Freshness bounds (SPEC §4.4 step 7 / PACT §13.1).
const (
	TSWindow    = 300 * time.Second
	MaxLifetime = 30 * 24 * time.Hour
)

// Payload is the plaintext of a request envelope (PACT §13.2): a bare JSON
// object, no JSON-RPC framing. `spk` carries the sender's SubjectPublicKeyInfo
// (base64url DER) and is required whenever the recipient does not pin `from`.
type Payload struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	SPK    string          `json:"spk,omitempty"`
}

// EnvelopeFacts is what a successfully opened envelope yields (SPEC §5.3).
type EnvelopeFacts struct {
	Header  envelope.Header
	From    string // the signer's fingerprint — the caller identity (2.0: the root's)
	SPKI    []byte // the sender's key: pinned, or carried as `spk` (2.0: the leaf's)
	Payload Payload
	Card    string // guest card from the inner call, when one was carried
	Guest   bool   // true when `from` was not in the contact store
	// PACT 2.0 (identify20.go). Protocol is 2 for a `v: 2` envelope; Tier is
	// what Decide resolved; Demote says a pin exists for From but the leaf
	// proved nothing for it (blocked, superseded), so the caller is a guest
	// whatever the pool would resolve; Endpoint and Leaf are the proven
	// address and certificate; Form is chain or leaf; Refusal is a code the
	// wrapper answers in plaintext (pending_approval) with nothing dispatched.
	Protocol     int
	Tier         policy.Tier
	Demote       bool
	Endpoint     string
	Leaf         []byte
	Form         string
	Why          string
	AddressClaim string
	Refusal      string
}

// Delivery says how the envelope reached the node: relay-delivered envelopes are
// exempt from the 300 s timestamp window (bounded by `exp` alone, §4.4 step 7).
type Delivery int

const (
	DeliveryDirect Delivery = iota
	DeliveryRelay
)

// IdempotencyStore records msg_id acknowledgments (SPEC §4.4 step 8).
type IdempotencyStore interface {
	PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (stored string, existed bool, err error)
}

// Identifier runs the pipeline for one node.
type Identifier struct {
	Store store.Store
	// AccountID is the account this identifier serves. One is built per account
	// (SPEC §5.2), so this is fixed for its lifetime.
	AccountID string
	// Keypair unseals the account's identity key (identity.Manager.LoadKeypair
	// over the stored sealed blob).
	Keypair func(ctx context.Context, accountID string) (*identity.Keypair, error)
	Seal    core.Seal
	Cert    core.ClientCert
	// SealFn, when set, overrides Seal per call. The settings page changes the
	// policy while the node is serving, and a switch that only takes effect on
	// the next restart is a footgun — so the gate reads through this rather
	// than a value captured when the surface was built.
	SealFn func() core.Seal
	Now    func() time.Time
	// Audit records refusals; nil discards.
	Audit func(action, resource, outcome string)
	// BindKey records a pinned-but-keyless contact's public key the first time
	// that key connects (SPEC §3.9). A contact re-pinned during rotation holds
	// only a fingerprint until then, and without this it would stay that way
	// forever — so we could never seal to them again.
	BindKey func(ctx context.Context, accountID, fpr string, spki []byte) error
	// State20 supplies what a `v: 2` envelope is decided against (PACT §13.3):
	// the keys this endpoint holds, the chain, the owner's settings. nil means
	// the identity speaks 1.x only. Read per call, so a setting the owner
	// changes takes effect without a restart.
	State20 func(ctx context.Context) (*State20, error)
	// OnEvent is told of a renewal or a new address learned from a chain
	// (PACT §5.3: shown to the owner as an event); OnPending of an address
	// awaiting the owner's answer. Both may be nil.
	OnEvent   func(event, root, endpoint string)
	OnPending func(root, endpoint, why string)
}

// bindIfKeyless records the presented key for a contact we hold only a
// fingerprint for. The store checks the hash matches the pin, so a wrong key
// cannot be bound; failures are deliberately ignored, because identification
// must not fail over a bookkeeping write.
func (id *Identifier) bindIfKeyless(ctx context.Context, accountID, fpr string, spki []byte) {
	if id.BindKey == nil || fpr == "" || len(spki) == 0 {
		return
	}
	c, err := id.Store.GetContact(ctx, accountID, fpr)
	if err != nil || len(c.SPKI) > 0 {
		return
	}
	_ = id.BindKey(ctx, accountID, fpr, spki)
}

func (id *Identifier) now() time.Time {
	if id.Now != nil {
		return id.Now()
	}
	return time.Now()
}

func (id *Identifier) audit(action, resource, outcome string) {
	if id.Audit != nil {
		id.Audit(action, resource, outcome)
	}
}

// fingerprintOf is PACT §2's identity function over an SPKI.
func fingerprintOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

type envelopeFactsKey struct{}

// WithEnvelopeFacts attaches opened-envelope facts to a dispatch context.
func WithEnvelopeFacts(ctx context.Context, f *EnvelopeFacts) context.Context {
	return context.WithValue(ctx, envelopeFactsKey{}, f)
}

// EnvelopeFactsFrom returns the facts of the envelope this call arrived in, or
// nil for a plaintext call.
func EnvelopeFactsFrom(ctx context.Context) *EnvelopeFacts {
	f, _ := ctx.Value(envelopeFactsKey{}).(*EnvelopeFacts)
	return f
}

// CallerSPKI is the ONE way a tool handler learns the caller's public key: from
// the envelope when the call was sealed, from the client certificate when it was
// not. Both paths carry the full key; neither ever infers it from a fingerprint.
func CallerSPKI(ctx context.Context) []byte {
	if f := EnvelopeFactsFrom(ctx); f != nil {
		return f.SPKI
	}
	return FactsFrom(ctx).ClientCertSPKI
}

// CallerCard is the card a guest carried inside a sealed envelope ("" otherwise).
func CallerCard(ctx context.Context) string {
	if f := EnvelopeFactsFrom(ctx); f != nil {
		return f.Card
	}
	return ""
}

// seal is the account's live seal policy.
func (id *Identifier) seal() core.Seal {
	if id.SealFn != nil {
		return id.SealFn()
	}
	return id.Seal
}

// PlaintextGateCtx is the policy check for an UNSEALED call (§4.4, §4.11, §5.1).
// tool is the inner tool name; substantive calls are everything except
// `sealed_call` and `tools/list`, which always answer with whatever identity
// the transport earned.
// The request's context carries the node's one-per-request resolution of a
// 2.0 chain (ResolveTransport); the gate enforces that resolution rather than
// re-deciding, so a re-pin or a pending address is recorded once per request,
// not once per tool call.
func (id *Identifier) PlaintextGateCtx(ctx context.Context, tf TransportFacts, tool string, substantive bool) (string, error) {
	// identity first: identity_required precedes seal_required (§4.11, §5.3)
	if id.Cert == core.ClientCertRequired && tf.ClientCertFingerprint == "" {
		id.audit("identity_gate", "account:"+id.AccountID+" tool:"+tool, "identity_required")
		return "", fmt.Errorf("%w: this node requires a client certificate", ErrIdentityRequired)
	}
	if substantive && id.seal() == core.SealRequired {
		if tf.ClientCertFingerprint == "" {
			id.audit("identity_gate", "account:"+id.AccountID+" tool:"+tool, "identity_required")
			return "", fmt.Errorf("%w: no identity was established", ErrIdentityRequired)
		}
		id.audit("identity_gate", "account:"+id.AccountID+" tool:"+tool, "seal_required")
		return "", fmt.Errorf("%w: this node requires sealed calls", ErrSealRequired)
	}
	// A 2.0 chain as the client certificate (PACT §2): the root is the caller
	// once the pin checks the sealed path makes have run (ResolveTransport):
	// a leaf older than the pinned one proves nothing (§14.3) and a blocked
	// root is a stranger — both an anonymous guest here; another address is
	// §5.3 — re-pinned under `auto`, parked under `ask` with every call
	// answered pending_approval until the owner decides.
	if tf.ClientProtocol == 2 {
		if id.speaks20(ctx) {
			tc, ok := TransportCallerFrom(ctx)
			if !ok {
				tc = id.ResolveTransport(ctx, tf)
			}
			if tc.Refusal != "" {
				if tool == "update_contact" {
					return "", ErrPendingStatus
				}
				id.audit("identity_gate", "account:"+id.AccountID+" contact:"+tf.ClientCertFingerprint+" tool:"+tool, tc.Refusal)
				return "", ErrPendingApproval
			}
			return tc.Fingerprint, nil
		}
		// PACT Appendix C row 4: a 1.x identity ignores the chain and reads
		// the leaf's key — so its pins stay keyed by key, which is what its
		// own `v: 1` exchanges resolve by until the account upgrades.
		tf.ClientCertFingerprint = fingerprintOfSPKI(tf.ClientCertSPKI)
	}
	// A contact re-pinned during rotation holds only a fingerprint (§3.9). This
	// is the moment their key reappears, so record it — otherwise we could never
	// seal to them again.
	id.bindIfKeyless(context.Background(), id.AccountID, tf.ClientCertFingerprint, tf.ClientCertSPKI)
	return tf.ClientCertFingerprint, nil
}

// speaks20 reports whether the account this identifier serves holds a leaf.
func (id *Identifier) speaks20(ctx context.Context) bool {
	if id.State20 == nil {
		return false
	}
	st, err := id.State20(ctx)
	return err == nil && st != nil && st.Protocol == 2
}

// LegacyCaller is the caller a 1.x account sees on the transport: the leaf's
// key when a chain was presented (PACT Appendix C row 4), else the certificate's.
func LegacyCaller(tf TransportFacts) string {
	if tf.ClientProtocol == 2 {
		return fingerprintOfSPKI(tf.ClientCertSPKI)
	}
	return tf.ClientCertFingerprint
}

// PoolGate adapts an Identifier into the Pool.Gate hook: it applies the
// plaintext rules of §5.1 to unsealed calls and lets sealed ones through, since
// those already ran the full open order in OpenSealed. `tools/list` never
// reaches here (the pool filters it without a handler), so every call this sees
// is substantive except the sealed_call wrapper itself.
func (id *Identifier) PoolGate() func(ctx context.Context, tool string) error {
	return func(ctx context.Context, tool string) error {
		if EnvelopeFactsFrom(ctx) != nil {
			return nil // sealed: already validated
		}
		_, err := id.PlaintextGateCtx(ctx, FactsFrom(ctx), tool, tool != SealedToolName)
		return err
	}
}

// OpenSealed runs the numbered open order (SPEC §4.4) for one sealed_call.
// accountID/accountFpr identify the addressed account; tf carries the transport
// facts of the connection the envelope arrived on.
func (id *Identifier) OpenSealed(ctx context.Context, accountID, accountFpr string, tf TransportFacts, e *envelope.Envelope, d Delivery) (*EnvelopeFacts, error) {
	// 0. Policy. At `none` the recipient does not accept envelopes (PACT §13.4)
	// — the card said not to seal, and this one check covers BOTH inbound
	// paths: the sealed_call wrapper and the relay fetch. Read live, like
	// PlaintextGate, so flipping the knob needs no restart.
	if id.seal() == core.SealNone {
		return nil, fmt.Errorf("%w: this recipient does not accept sealed calls", ErrSealNotAccepted)
	}
	// The two generations part on `v` before either header parser runs: a
	// `v: 2` header has no from and no to, and its rules are the library's
	// (PACT §13.3); a `v: 1` one is a 1.x proof and takes the order below.
	if peekVersion(e.Protected) == 2 {
		return id.openSealed2(ctx, accountID, tf, e)
	}
	if id.State20 != nil {
		if st, err := id.State20(ctx); err == nil && st != nil && st.Protocol == 2 && !st.Accept1x {
			return nil, fmt.Errorf("%w: this identity no longer accepts 1.x proofs", envelope.ErrInvalid)
		}
	}
	// 1. Decode + 2. Suite (ParseHeader enforces v and the suite enum).
	h, err := envelope.ParseHeader(e)
	if err != nil {
		return nil, err
	}
	// A replay guard keyed on an empty string protects nothing (PACT §13.1:
	// msg_id is REQUIRED and non-empty).
	if h.MsgID == "" {
		return nil, fmt.Errorf("%w: envelope carries no msg_id", envelope.ErrInvalid)
	}
	// 3. Addressing + 4. Key id. In 1.x both name the account's identity key
	// (§4.10); a node that has renewed still holds the superseded key until its
	// notAfter, so a 1.x contact that has not re-pinned is still answered.
	if !id.holdsKey(ctx, accountFpr, h.To) {
		return nil, fmt.Errorf("%w: envelope is addressed to %s, not this account", envelope.ErrInvalid, h.To)
	}
	kp, err := id.resolveKey(ctx, accountID, accountFpr, h.KID)
	if err != nil {
		return nil, err
	}
	// suite must match the addressed account's key type
	if want := envelope.SuiteForKey(kp); want != h.Suite {
		return nil, fmt.Errorf("%w: suite %q does not match this account's key", envelope.ErrInvalid, h.Suite)
	}
	// 5. Open. HPKE Base needs no sender key.
	plain, err := envelope.Open(kp, e)
	if err != nil {
		return nil, err
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", envelope.ErrInvalid, err)
	}
	if p.Method != "tools/call" && p.Method != "tools/list" {
		return nil, fmt.Errorf("%w: inner method %q", envelope.ErrInvalid, p.Method)
	}

	// 6. Verify the signature.
	facts := &EnvelopeFacts{Header: h, From: h.From, Payload: p}
	contact, contactErr := id.Store.GetContact(ctx, accountID, h.From)
	// A BLOCKED sender is held to the guest rules, byte-identically to an unknown
	// one (§4.4, §9.1): spk required, card required, sealed tools/list refused.
	// Verifying it against its pin instead would make acceptance itself the
	// oracle that distinguishes "blocked" from "never met".
	pinned := contactErr == nil && len(contact.SPKI) > 0 && contact.Status != "blocked"

	// A contact re-pinned by a rotation holds only a FINGERPRINT until its key
	// reappears (§3.9, escalation E7). The only place that recorded it needed an
	// mTLS certificate, and two shipped delivery paths have none: a relayed
	// envelope carries no transport facts at all, and edge mode forces client
	// certificates off. On those paths the contact fell through to the guest
	// branch, which demands a card `send_message` does not carry — so rotation
	// was contact LOSS for exactly the deployments that need a relay or an edge,
	// which is the failure P10-09a set out to fix.
	//
	// The envelope carries the key. Binding it here is the same rule the guest
	// branch already applies — the key must hash to `from` — with `from` also
	// having to equal a fingerprint this node chose to pin.
	if !pinned && contactErr == nil && len(contact.SPKI) == 0 &&
		contact.Status != "blocked" && p.SPK != "" {
		if spki, err := decodeSPK(p.SPK); err == nil && fingerprintOf(spki) == h.From {
			if id.BindKey != nil {
				_ = id.BindKey(ctx, accountID, h.From, spki)
			}
			contact.SPKI = spki
			pinned = true
			id.audit("contact_key_bound", "account:"+id.AccountID+" contact:"+h.From, "sealed")
		}
	}

	if pinned {
		if err := verifyWith(e, contact.SPKI); err != nil {
			return nil, err
		}
		if p.SPK != "" {
			spki, err := decodeSPK(p.SPK)
			if err != nil {
				return nil, err
			}
			if string(spki) != string(contact.SPKI) {
				return nil, fmt.Errorf("%w: spk does not match the pinned key for %s", envelope.ErrInvalid, h.From)
			}
		}
		facts.SPKI = contact.SPKI
	} else {
		// Guest: the key rides in the payload, bound by hash to `from` and the card.
		facts.Guest = true
		if p.SPK == "" {
			return nil, fmt.Errorf("%w: an unpinned sender must carry spk", envelope.ErrInvalid)
		}
		spki, err := decodeSPK(p.SPK)
		if err != nil {
			return nil, err
		}
		if fingerprintOf(spki) != h.From {
			return nil, fmt.Errorf("%w: spk does not hash to from", envelope.ErrInvalid)
		}
		if err := verifyWith(e, spki); err != nil {
			return nil, err
		}
		card, err := guestCard(p)
		if err != nil {
			return nil, err
		}
		if contacts.CardKey(card) != h.From {
			return nil, fmt.Errorf("%w: card X-PACT-KEY does not match the signing key", envelope.ErrInvalid)
		}
		facts.SPKI, facts.Card = spki, card
	}
	// Unified identity rule (§5.3): both proofs present ⇒ they MUST match. A
	// chain on the transport names its leaf's key here (PACT Appendix C row
	// 4): a `v: 1` envelope's `from` is that key's fingerprint.
	if tf.ClientCertFingerprint != "" && LegacyCaller(tf) != h.From {
		id.audit("identity_mismatch", "account:"+id.AccountID+" contact:"+h.From, "envelope_invalid")
		return nil, fmt.Errorf("%w: client certificate %s does not match envelope signer %s",
			envelope.ErrInvalid, tf.ClientCertFingerprint, h.From)
	}

	// 7. Freshness.
	now := id.now().Unix()
	if h.Exp <= now {
		return nil, fmt.Errorf("%w: envelope expired", envelope.ErrInvalid)
	}
	if h.Exp-h.TS > int64(MaxLifetime/time.Second) {
		return nil, fmt.Errorf("%w: lifetime exceeds 30 days", envelope.ErrInvalid)
	}
	if d == DeliveryDirect {
		if skew := now - h.TS; skew > int64(TSWindow/time.Second) || skew < -int64(TSWindow/time.Second) {
			return nil, fmt.Errorf("%w: timestamp outside the 300 s window", envelope.ErrInvalid)
		}
	}
	return facts, nil
}

// Replay checks step 8: a msg_id already processed for this caller returns its
// recorded acknowledgment instead of re-executing. Reserving before dispatch
// and finalizing after is the caller's job (the ack text is the tool result).
// EnvelopeKey namespaces an envelope's replay guard away from tool-level
// idempotency. SPEC §4.5 keeps the two separate on purpose — "the envelope
// msg_id deduplicates the envelope; an inner tool that itself takes a msg_id
// (e.g. send_message, book_slot) keeps its own tool-level idempotency
// unchanged" — but both were reserving the SAME (account, contact, msg_id) row.
//
// call_contact sends the tool's msg_id as the envelope's (that is what makes a
// retried call idempotent end to end), so a sealed book_slot reserved the id as
// an envelope, then the calendar provider tried to reserve it again and read its
// own reservation as another attempt in flight. Every sealed booking failed
// with "unavailable"; unsealed ones worked, which is why the direct scenario
// passed. The prefix is storage-local and invisible on the wire.
func EnvelopeKey(msgID string) string { return "env:" + msgID }

func (id *Identifier) Replay(ctx context.Context, idem IdempotencyStore, accountID string, f *EnvelopeFacts) (ack string, replayed bool, err error) {
	if idem == nil || f.Header.MsgID == "" {
		return "", false, nil
	}
	stored, existed, err := idem.PutIdempotency(ctx, accountID, f.From, EnvelopeKey(f.Header.MsgID), "", f.Header.Exp)
	if err != nil {
		return "", false, err
	}
	if existed && stored != "" {
		return stored, true, nil
	}
	return "", false, nil
}

func verifyWith(e *envelope.Envelope, spki []byte) error {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("%w: unreadable sender key", envelope.ErrInvalid)
	}
	return envelope.VerifySig(e, pub)
}

func decodeSPK(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("%w: spk is not base64url DER", envelope.ErrInvalid)
	}
	if _, err := x509.ParsePKIXPublicKey(b); err != nil {
		return nil, fmt.Errorf("%w: spk is not a SubjectPublicKeyInfo", envelope.ErrInvalid)
	}
	return b, nil
}

// guestCard pulls the `card` argument out of an inner tools/call. A guest
// envelope whose inner request is tools/list — or whose call has no card — is
// rejected: there is nothing to bind the signature to (§4.4 step 6).
func guestCard(p Payload) (string, error) {
	if p.Method != "tools/call" {
		return "", fmt.Errorf("%w: a guest may not seal %s", envelope.ErrInvalid, p.Method)
	}
	var call struct {
		Name      string `json:"name"`
		Arguments struct {
			Card string `json:"card"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(p.Params, &call); err != nil {
		return "", fmt.Errorf("%w: inner params: %v", envelope.ErrInvalid, err)
	}
	if call.Arguments.Card == "" {
		return "", fmt.Errorf("%w: a guest call must carry a card", envelope.ErrInvalid)
	}
	return call.Arguments.Card, nil
}
