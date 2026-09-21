package public

// PACT 2.0 receiving (PACT §13.3, §6.1, §5.3, §14.3, §14.4): a `v: 2`
// envelope is decided by the library's pure Decide over the state this node
// supplies, and the effects it returns are applied here — the pin that
// follows a newer leaf or a new address, the former endpoint, the pending
// address the owner must answer, the event the owner is shown. The library
// holds no state and never touches the store; this file is the seam.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// ErrChainRequired is PACT §13.2's uniform answer to a small-form envelope the
// receiver cannot verify against a leaf it holds: unknown, blocked, expired,
// or a bad signature — one answer, so nothing leaks. It travels in plaintext
// and is charged to the guest budget (§14.5).
var ErrChainRequired = errors.New("chain_required")

// CertificateRenewed is PACT §14.4: an envelope sealed to a key this endpoint
// once held for the identity and holds no longer is answered, in plaintext,
// with the identity's current chain.
type CertificateRenewed struct{ Chain [][]byte }

func (e *CertificateRenewed) Error() string { return "certificate_renewed" }

// TierPendingAddress is the seed's fourth outcome: a pinned root at a new
// address under `ask`, or one returned after a removal. It is not a tier the
// pool knows; the call answers `{"status": "pending"}` and nothing runs.
const TierPendingAddress policy.Tier = "pending_new_address"

// State20 is everything Decide reads about this account, supplied per call so
// a setting the owner changes takes effect without a restart.
type State20 struct {
	// HasRoot is whether the wallet has issued this identity a leaf: until it has, there is no
	// chain to speak under and nothing sealed can be opened (PACT §2).
	HasRoot        bool
	Endpoint       string
	AcceptNewHosts string
	Chain          [][]byte           // [current leaf, root]
	Keys           []identity.LeafKey // current first, superseded until notAfter
	Former         []string           // kids once held (§14.4)
	SiblingKids    []string           // kids held for other identities on this origin
}

// currentKey is the leaf key that signs and seals today.
func (s *State20) currentKey() *identity.Keypair {
	for _, k := range s.Keys {
		if k.Current {
			return k.KP
		}
	}
	return nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// nodeState builds Decide's input from the store and the supplied state.
func (id *Identifier) nodeState(ctx context.Context, accountID string, st *State20) (pactidentity.NodeState, error) {
	ns := pactidentity.NodeState{
		Endpoint: st.Endpoint, AcceptNewHosts: st.AcceptNewHosts, Former: st.Former, SiblingKids: st.SiblingKids,
	}
	if ns.AcceptNewHosts == "" {
		ns.AcceptNewHosts = "auto"
	}
	for _, c := range st.Chain {
		ns.Chain = append(ns.Chain, b64u(c))
	}
	for _, k := range st.Keys {
		der, err := identity.MarshalPKCS8(k.KP)
		if err != nil {
			return ns, err
		}
		ns.Keys = append(ns.Keys, pactidentity.HeldKey{Kid: k.Kid, Leaf: b64u(k.Leaf), PKCS8: b64u(der), Current: k.Current})
	}
	contacts, err := id.Store.ListContacts(ctx, accountID)
	if err != nil {
		return ns, err
	}
	for _, c := range contacts {
		if len(c.Leaf) > 0 {
			ns.Pins = append(ns.Pins, pactidentity.Pin{Root: c.Fingerprint, Endpoint: c.Endpoint, Leaf: b64u(c.Leaf), State: c.Status})
		}
	}
	tombs, err := id.Store.ListTombstones(ctx, accountID)
	if err != nil {
		return ns, err
	}
	for _, t := range tombs {
		ns.Tombstones = append(ns.Tombstones, pactidentity.TombstoneRec{Root: t.Root, Leaf: b64u(t.Leaf), At: time.Unix(t.At, 0).UTC().Format(time.RFC3339)})
	}
	formers, err := id.Store.ListFormerEndpoints(ctx, accountID)
	if err != nil {
		return ns, err
	}
	for _, f := range formers {
		ns.FormerEndpoints = append(ns.FormerEndpoints, pactidentity.FormerEndpoint{Root: f.Root, Endpoint: f.Endpoint, At: time.Unix(f.At, 0).UTC().Format(time.RFC3339)})
	}
	return ns, nil
}

// openSealed2 is the `v: 2` half of OpenSealed.
func (id *Identifier) openSealed2(ctx context.Context, accountID string, tf TransportFacts, e *envelope.Envelope) (*EnvelopeFacts, error) {
	if id.State20 == nil {
		return nil, fmt.Errorf("%w: this identity does not speak 2.0", envelope.ErrInvalid)
	}
	st, err := id.State20(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	if st == nil || !st.HasRoot {
		return nil, fmt.Errorf("%w: this identity has no certificate yet", envelope.ErrInvalid)
	}
	wire := pactidentity.Envelope{Protected: b64u(e.Protected), Enc: b64u(e.Enc), Ct: b64u(e.CT), Sig: b64u(e.Sig)}
	now := id.now()
	ns, err := id.nodeState(ctx, accountID, st)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	d, err := pactidentity.Decide(now, wire, ns)
	if err != nil {
		// Not the envelope: a row of THIS node's state — a held key's leaf, a pin, a tombstone —
		// would not read. The port used to step over such a row and decide without it, which quietly
		// answered `chain_required` to a contact and made a peer returning after removal a plain
		// guest. The peer is told what it is told whenever state cannot be loaded; the owner is told
		// which account and why, because only they can mend it.
		id.audit("identity_state_unreadable", "account:"+accountID+" why:"+err.Error(), "error")
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	code, _ := d.Result["code"].(string)
	switch code {
	case "envelope_invalid":
		why, _ := d.Result["why"].(string)
		return nil, fmt.Errorf("%w: %s", envelope.ErrInvalid, why)
	case "chain_required":
		return nil, ErrChainRequired
	case "certificate_renewed":
		var chain [][]byte
		if data, ok := d.Result["data"].(map[string]any); ok {
			if cs, ok := data["chain"].([]any); ok {
				for _, c := range cs {
					if s, ok := c.(string); ok {
						chain = append(chain, pactidentity.FromB64url(s))
					}
				}
			}
		}
		return nil, &CertificateRenewed{Chain: chain}
	case "pending_approval":
		// A pin in `pending_out` calling something other than contact_accepted or
		// contact_rejected: the contact request has not been answered yet, so
		// nothing else runs. (A new address the owner has not approved is the
		// `pending_new_address` tier below, not this.) Answered as a plain code,
		// before any tier is earned; the decision carried no effects to apply.
		return &EnvelopeFacts{Refusal: "pending_approval"}, nil
	case "ok":
	default:
		return nil, fmt.Errorf("%w: undecided", envelope.ErrInvalid)
	}
	if replayed, _ := d.Result["replayed"].(bool); replayed {
		return nil, fmt.Errorf("%w: replay decided without state", envelope.ErrInvalid)
	}
	tier, _ := d.Result["tier"].(string)
	root, _ := d.Result["root"].(string)
	endpoint, _ := d.Result["endpoint"].(string)
	form, _ := d.Result["form"].(string)
	method, _ := d.Result["method"].(string)
	why, _ := d.Result["why"].(string)
	leafDER := pactidentity.FromB64url(func() string { s, _ := d.Result["leaf"].(string); return s }())
	leaf, err := pactidentity.Parse(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w: decided leaf unreadable", envelope.ErrInvalid)
	}
	params, _ := json.Marshal(d.Result["params"])
	if d.Result["params"] == nil {
		params = nil
	}
	var h envelope.Header
	_ = json.Unmarshal(e.Protected, &h)
	facts := &EnvelopeFacts{
		Header: h, From: root, SPKI: leaf.SPKI, Payload: Payload{Method: method, Params: params},
		Tier: policy.Tier(tier), Endpoint: endpoint, Leaf: leafDER, Form: form, Why: why,
	}
	if claim, ok := d.Result["address_claim"].(string); ok {
		facts.AddressClaim = claim
	}
	switch tier {
	case "guest":
		facts.Guest = true
		// A pin exists but the leaf proves nothing for it: blocked, or older
		// than the pinned one (§14.3). The pool would resolve the root to its
		// row; the envelope says guest, and the envelope wins.
		facts.Demote = why == "blocked" || why == "superseded leaf"
		var call struct {
			Arguments struct {
				Card string `json:"card"`
			} `json:"arguments"`
		}
		_ = json.Unmarshal(params, &call)
		facts.Card = call.Arguments.Card
	case "pending_new_address":
		facts.Tier = TierPendingAddress
	}
	// Unified identity rule (§2): both proofs present ⇒ their leaf keys MUST match.
	if len(tf.ClientCertSPKI) > 0 && !bytes.Equal(tf.ClientCertSPKI, leaf.SPKI) {
		id.audit("identity_mismatch", "account:"+id.AccountID+" contact:"+root, "envelope_invalid")
		return nil, fmt.Errorf("%w: client certificate key does not match the envelope's leaf", envelope.ErrInvalid)
	}
	if err := id.apply(ctx, accountID, d.Effects, now); err != nil {
		return nil, fmt.Errorf("%w: recording the decision: %v", envelope.ErrInvalid, err)
	}
	return facts, nil
}

// apply records what Decide decided: the effects are the host's to apply in
// the order returned. `seen` is left to Replay, which reserves the msg_id and
// stores the real acknowledgment.
func (id *Identifier) apply(ctx context.Context, accountID string, effects []map[string]any, now time.Time) error {
	for _, ef := range effects {
		op, _ := ef["op"].(string)
		root, _ := ef["root"].(string)
		endpoint, _ := ef["endpoint"].(string)
		switch op {
		case "seen":
		case "pin_update":
			leafDER := pactidentity.FromB64url(func() string { s, _ := ef["leaf"].(string); return s }())
			leaf, err := pactidentity.Parse(leafDER)
			if err != nil {
				return err
			}
			if err := id.Store.RepinContactAddress(ctx, accountID, root, endpoint, leafDER, leaf.SPKI, now.Unix()); err != nil {
				return err
			}
		case "former_endpoint":
			if err := id.Store.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: accountID, Root: root, Endpoint: endpoint, At: now.Unix()}); err != nil {
				return err
			}
		case "pending":
			why, _ := ef["why"].(string)
			leafDER := pactidentity.FromB64url(func() string { s, _ := ef["leaf"].(string); return s }())
			// No root certificate on this path: the chain the sender carried is inside
			// the ciphertext, and only the library's Decide ever sees it. The pending
			// row keeps the leaf; the cert arrives if that host connects with a client
			// certificate (migration 0029).
			if err := id.notePendingAddress(ctx, accountID, root, endpoint, why, leafDER, nil, now); err != nil {
				return err
			}
		case "event":
			event, _ := ef["event"].(string)
			id.audit("contact_"+event, "account:"+id.AccountID+" contact:"+root+" endpoint:"+endpoint, "ok")
			if id.OnEvent != nil {
				id.OnEvent(event, root, endpoint)
			}
		}
	}
	return nil
}

// notePendingAddress records a contact waiting at a new address, and audits and
// notifies ONLY when something about it changed.
//
// Every request from an unapproved address used to append an audit-chain row and
// fire the owner's notification: a host holding a still-valid leaf for a pinned
// root — a former host after a move, or a compromised one — grew the chain and
// the owner's feed one row per request, for as long as it kept calling. The row
// itself is idempotent; the telling is what had to become so.
func (id *Identifier) notePendingAddress(ctx context.Context, accountID, root, endpoint, why string, leafDER, rootCert []byte, now time.Time) error {
	prev, err := id.Store.GetPendingAddress(ctx, accountID, root)
	unchanged := err == nil && prev.Root == root && prev.Endpoint == endpoint && prev.Why == why
	if err := id.Store.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: accountID, Root: root, Endpoint: endpoint, Leaf: leafDER, Why: why, At: now.Unix(), RootCert: rootCert}); err != nil {
		return err
	}
	if unchanged {
		return nil
	}
	id.audit("contact_new_address", "account:"+accountID+" contact:"+root+" endpoint:"+endpoint+" why:"+why, "pending")
	if id.OnPending != nil {
		id.OnPending(root, endpoint, why)
	}
	return nil
}

// TransportCaller is what a 2.0 client certificate chain earned once the pin
// checks of PACT §14.3 and §5.3 have run — the same outcomes the sealed path
// reaches through Decide, so a chain presented at the TLS layer can do nothing
// an envelope carrying it could not. Fingerprint is the identity the per-caller
// server is composed for and the session is bound to: the root when the pin
// stands, "" — an anonymous guest — when the leaf proved nothing for it (a
// superseded or conflicting leaf, a blocked contact). Refusal names the code
// every substantive call answers while a new address awaits the owner.
type TransportCaller struct {
	Fingerprint string
	Demote      bool
	Refusal     string
}

type transportCallerKey struct{}

// WithTransportCaller attaches a resolution the node made once per request.
func WithTransportCaller(ctx context.Context, tc TransportCaller) context.Context {
	return context.WithValue(ctx, transportCallerKey{}, tc)
}

// TransportCallerFrom returns the request's resolution, if the node made one.
func TransportCallerFrom(ctx context.Context) (TransportCaller, bool) {
	tc, ok := ctx.Value(transportCallerKey{}).(TransportCaller)
	return tc, ok
}

// ResolveTransport applies the pin checks to a validated client chain and
// records what they change, exactly as the sealed path does through Decide's
// effects (identify20.go apply): a newer leaf at the pinned endpoint replaces
// it; another endpoint is §5.3 — re-pinned with the former endpoint and the
// owner's event under `auto`, parked as a pending address under `ask`, and
// and under `ask` after a removal within the tombstone window. It runs once per
// request, before the per-caller server is composed and the session bound,
// and its result is what PoolGate enforces on every call.
func (id *Identifier) ResolveTransport(ctx context.Context, tf TransportFacts) TransportCaller {
	root := tf.ClientCertFingerprint
	if !tf.ChainProven() || root == "" {
		return TransportCaller{Fingerprint: root}
	}
	leaf, err := pactidentity.Parse(tf.ClientLeaf)
	if err != nil || len(leaf.URIs) != 1 {
		return TransportCaller{}
	}
	endpoint := leaf.URIs[0]
	now := id.now()
	c, err := id.Store.GetContact(ctx, id.AccountID, root)
	if err != nil {
		return TransportCaller{Fingerprint: root} // the store resolves a stranger to guest
	}
	if len(c.Leaf) == 0 {
		return TransportCaller{Fingerprint: root}
	}
	if c.Status == "blocked" {
		// Served as a stranger, and indistinguishable from one (§6.1, §13.3).
		return TransportCaller{Demote: true}
	}
	// This is where a pin without its root certificate gets one (migration 0029):
	// the chain that just validated carries the root, and a pin made over a sealed
	// call never saw it. Never overwrites — the root of a pin cannot change — and a
	// failure is not fatal to the request, which is about the caller, not the column.
	if len(c.RootCert) == 0 && len(tf.ClientRoot) > 0 {
		if err := id.Store.SetContactRootCert(ctx, id.AccountID, root, tf.ClientRoot); err != nil {
			id.audit("contact_root_cert", "account:"+id.AccountID+" contact:"+root, "error")
		}
	}
	cmp, err := pactidentity.CompareLeaves(c.Leaf, tf.ClientLeaf)
	if err != nil || cmp == "superseded" || cmp == "conflict" {
		id.audit("identity_gate", "account:"+id.AccountID+" contact:"+root, "superseded_leaf")
		return TransportCaller{Demote: true}
	}
	if endpoint != c.Endpoint {
		policy := "auto"
		if id.State20 != nil {
			if st, serr := id.State20(ctx); serr == nil && st != nil && st.AcceptNewHosts != "" {
				policy = st.AcceptNewHosts
			}
		}
		why := "ask"
		if policy == "auto" {
			// A tombstoned root returning within the window is `ask` whatever
			// the setting says (§5.3, "after a removal").
			if tombs, terr := id.Store.ListTombstones(ctx, id.AccountID); terr == nil {
				for _, tb := range tombs {
					if tb.Root == root && now.Sub(time.Unix(tb.At, 0)) < 30*24*time.Hour {
						why = "returned after removal"
						policy = "ask"
					}
				}
			}
		}
		if policy != "auto" {
			_ = id.notePendingAddress(ctx, id.AccountID, root, endpoint, why, leaf.DER, tf.ClientRoot, now)
			// Until the owner decides, the pin stands where it was and nothing
			// from the new address runs: the caller is composed as an anonymous
			// guest and every substantive call is refused pending_approval.
			return TransportCaller{Demote: true, Refusal: "pending_approval"}
		}
		if err := id.Store.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: id.AccountID, Root: root, Endpoint: c.Endpoint, At: now.Unix()}); err != nil {
			return TransportCaller{Demote: true}
		}
		if err := id.Store.RepinContactAddress(ctx, id.AccountID, root, endpoint, leaf.DER, leaf.SPKI, now.Unix()); err != nil {
			return TransportCaller{Demote: true}
		}
		id.audit("contact_new_address", "account:"+id.AccountID+" contact:"+root+" endpoint:"+endpoint, "ok")
		if id.OnEvent != nil {
			id.OnEvent("new_address", root, endpoint)
		}
		return TransportCaller{Fingerprint: root}
	}
	if cmp == "newer" {
		if err := id.Store.RepinContactAddress(ctx, id.AccountID, root, endpoint, leaf.DER, leaf.SPKI, now.Unix()); err != nil {
			return TransportCaller{Demote: true}
		}
		id.audit("contact_renewal", "account:"+id.AccountID+" contact:"+root+" endpoint:"+endpoint, "ok")
		if id.OnEvent != nil {
			id.OnEvent("renewal", root, endpoint)
		}
	}
	return TransportCaller{Fingerprint: root}
}
