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
// lets a sender this node has never pinned carry its chain inside the
// ciphertext (PACT §13.2).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
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

// Payload is the call an opened request envelope carries (PACT §13.2): the
// method and its params, as the library's Decide read them out of the
// plaintext. The sender's chain or leaf, which the same plaintext carries, is
// decided there and reaches the node as EnvelopeFacts, not as a member here.
type Payload struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// EnvelopeFacts is what a successfully opened envelope yields (SPEC §5.3).
type EnvelopeFacts struct {
	Header  envelope.Header
	From    string // the signer's fingerprint — the caller identity (2.0: the root's)
	SPKI    []byte // the sender's key: the leaf's, from the chain or the pin
	Payload Payload
	Card    string // guest card from the inner call, when one was carried
	Guest   bool   // true when `from` was not in the contact store
	// PACT 2.0 (identify20.go). Protocol is 2 for a `v: 2` envelope; Tier is
	// what Decide resolved; Demote says a pin exists for From but the leaf
	// proved nothing for it (blocked, superseded), so the caller is a guest
	// whatever the pool would resolve; Endpoint and Leaf are the proven
	// address and certificate; Form is chain or leaf; Refusal is a code the
	// wrapper answers in plaintext (pending_approval) with nothing dispatched.
	Tier         policy.Tier
	Demote       bool
	Endpoint     string
	Leaf         []byte
	Form         string
	Why          string
	AddressClaim string
	Refusal      string
}

// IdempotencyStore records msg_id acknowledgments (SPEC §4.4 step 8).
type IdempotencyStore interface {
	PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (stored string, existed bool, err error)
}

// Identifier runs the pipeline for one node.
type Identifier struct {
	Store store.ContactStore
	// AccountID is the account this identifier serves. One is built per account
	// (SPEC §5.2), so this is fixed for its lifetime.
	AccountID string
	Seal      core.Seal
	Cert      core.ClientCert
	// SealFn, when set, overrides Seal per call. The settings page changes the
	// policy while the node is serving, and a switch that only takes effect on
	// the next restart is a footgun — so the gate reads through this rather
	// than a value captured when the surface was built.
	SealFn func() core.Seal
	Now    func() time.Time
	// Audit records refusals; nil discards.
	Audit func(action, resource, outcome string)
	// State20 supplies what a `v: 2` envelope is decided against (PACT §13.3):
	// the keys this endpoint holds, the chain, the owner's settings. Read per
	// call, so a setting the owner
	// changes takes effect without a restart.
	State20 func(ctx context.Context) (*State20, error)
	// OnEvent is told of a renewal or a new address learned from a chain
	// (PACT §5.3: shown to the owner as an event); OnPending of an address
	// awaiting the owner's answer. Both may be nil.
	OnEvent   func(event, root, endpoint string)
	OnPending func(root, endpoint, why string)
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
	// identity first: identity_required precedes seal_required (§4.11, §5.3).
	// "A certificate" means a chain that validated (PACT §14.2) and nothing
	// else — the posture PACT §13.4 permits is about who may knock at all, and
	// a lone self-signed certificate is not a knock anyone can be held to.
	if id.Cert == core.ClientCertRequired && !tf.ChainProven() {
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
	if tf.ChainProven() {
		if id.speaks20(ctx) {
			tc, ok := TransportCallerFrom(ctx)
			if !ok {
				tc = id.ResolveTransport(ctx, tf)
			}
			if tc.Refusal != "" {
				// A `sealed_call` is answered by its envelope, not here. The envelope carries the
				// same chain, meets the same §5.3 decision in `identify20`, and its refusal goes
				// back SEALED (PACT §13.2) — whereas refusing at this gate answered in plaintext
				// before anything was opened. A caller that holds §13.2 to its word reads a
				// plaintext `pending_approval` to a sealed call as forged, so a contact presenting
				// both proofs from a new address — a sealed move announcement over mTLS, say — was
				// told nothing it could believe. The transport earns no identity for this request;
				// the both-proofs key match (PACT §2) still runs on the facts, and the envelope
				// decides.
				if tool == "sealed_call" {
					return "", nil
				}
				if tool == "update_contact" {
					return "", ErrPendingStatus
				}
				id.audit("identity_gate", "account:"+id.AccountID+" contact:"+tf.ClientCertFingerprint+" tool:"+tool, tc.Refusal)
				return "", ErrPendingApproval
			}
			return tc.Fingerprint, nil
		}
	}
	return tf.ClientCertFingerprint, nil
}

// speaks20 reports whether the account this identifier serves holds a leaf.
func (id *Identifier) speaks20(ctx context.Context) bool {
	if id.State20 == nil {
		return false
	}
	st, err := id.State20(ctx)
	return err == nil && st != nil && st.HasRoot
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
// accountID is the addressed account; tf carries the transport
// facts of the connection the envelope arrived on.
func (id *Identifier) OpenSealed(ctx context.Context, accountID string, tf TransportFacts, e *envelope.Envelope) (*EnvelopeFacts, error) {
	// 0. Policy. At `none` the recipient does not accept envelopes (PACT §13.4)
	// — the card said not to seal. The sealed_call wrapper is the only way an
	// envelope arrives, and it opens through here. Read live, like
	// PlaintextGate, so flipping the knob needs no restart.
	if id.seal() == core.SealNone {
		return nil, fmt.Errorf("%w: this recipient does not accept sealed calls", ErrSealNotAccepted)
	}
	// Every envelope is `v: 2` (PACT §13.1): the header has no `from` and no `to`,
	// and the open order is the library's (§13.3). A header whose `v` is anything
	// else is refused there.
	return id.openSealed2(ctx, accountID, tf, e)
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
