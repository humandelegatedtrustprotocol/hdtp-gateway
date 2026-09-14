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
	Protocol       int
	Endpoint       string
	AcceptNewHosts string
	Accept1x       bool
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

// keyFor resolves an envelope's kid to a key this endpoint still holds.
func (s *State20) keyFor(kid string) *identity.Keypair {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k.KP
		}
	}
	return nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// peekVersion reads `v` and nothing else, so the two generations can part
// before either parser applies its own rules to the header.
func peekVersion(protected []byte) int {
	var h struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(protected, &h); err != nil {
		return 0
	}
	return h.V
}

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
		if c.Protocol == 2 && len(c.Leaf) > 0 {
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
	if st == nil || st.Protocol != 2 {
		return nil, fmt.Errorf("%w: this identity does not speak 2.0", envelope.ErrInvalid)
	}
	wire := pactidentity.Envelope{Protected: b64u(e.Protected), Enc: b64u(e.Enc), Ct: b64u(e.CT), Sig: b64u(e.Sig)}
	now := id.now()
	ns, err := id.nodeState(ctx, accountID, st)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	d := pactidentity.Decide(now, wire, ns)
	code, _ := d.Result["code"].(string)
	// Appendix C row 6: a 1.x pin of key K, met by a chain whose leaf key is
	// K, becomes the 2.0 pin of that root with no human step — and the call is
	// then decided as the contact it always was. The unknown root shows as a
	// guest, or as a guest refused a contact's tool; both name the leaf.
	if why, _ := d.Result["why"].(string); why == "unknown root" || why == "guest may only redeem or request" {
		if id.upgradeLegacyPin(ctx, accountID, d.Result, now) {
			if ns, err = id.nodeState(ctx, accountID, st); err == nil {
				d = pactidentity.Decide(now, wire, ns)
				code, _ = d.Result["code"].(string)
			}
		}
	}
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
		// The seed answers this as a plain code, before any tier is earned: a
		// pinned root at a new address the owner has not yet approved (§5.3).
		return &EnvelopeFacts{Protocol: 2, Refusal: "pending_approval"}, nil
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
		Protocol: 2, Tier: policy.Tier(tier), Endpoint: endpoint, Leaf: leafDER, Form: form, Why: why,
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

// upgradeLegacyPin re-pins a 1.x contact whose pinned key is the leaf key of a
// validated chain (PACT Appendix C row 6). It reports whether a pin changed.
func (id *Identifier) upgradeLegacyPin(ctx context.Context, accountID string, result map[string]any, now time.Time) bool {
	leafB64, _ := result["leaf"].(string)
	leaf, err := pactidentity.Parse(pactidentity.FromB64url(leafB64))
	if err != nil {
		return false
	}
	keyFpr := pactidentity.Fingerprint(leaf.SPKI)
	c, err := id.Store.GetContact(ctx, accountID, keyFpr)
	if err != nil || c.Protocol == 2 || c.Status == "blocked" {
		return false
	}
	root, _ := result["root"].(string)
	endpoint, _ := result["endpoint"].(string)
	if err := id.Store.UpgradeContactPin(ctx, accountID, keyFpr, root, endpoint, leaf.DER, leaf.SPKI, now.Unix()); err != nil {
		return false
	}
	id.audit("contact_upgraded", "account:"+id.AccountID+" contact:"+root+" key:"+keyFpr, "ok")
	return true
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
			if err := id.Store.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: accountID, Root: root, Endpoint: endpoint, Leaf: leafDER, Why: why, At: now.Unix()}); err != nil {
				return err
			}
			id.audit("contact_new_address", "account:"+id.AccountID+" contact:"+root+" endpoint:"+endpoint+" why:"+why, "pending")
			if id.OnPending != nil {
				id.OnPending(root, endpoint, why)
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

// holdsKey reports whether a fingerprint names a key this account serves under:
// its identity key, or a leaf key held today (current or superseded).
func (id *Identifier) holdsKey(ctx context.Context, accountFpr, fpr string) bool {
	if fpr == accountFpr {
		return true
	}
	if id.State20 != nil {
		if st, err := id.State20(ctx); err == nil && st != nil && st.keyFor(fpr) != nil {
			return true
		}
	}
	return false
}

// resolveKey is the `v: 1` kid step for a node that may hold more than one
// key: the current leaf's and superseded ones until their notAfter (PACT §2),
// which is also what serves a 1.x rotation's retiring key on the inbound path.
func (id *Identifier) resolveKey(ctx context.Context, accountID, accountFpr, kid string) (*identity.Keypair, error) {
	if id.State20 != nil {
		if st, err := id.State20(ctx); err == nil && st != nil {
			if kp := st.keyFor(kid); kp != nil {
				return kp, nil
			}
			if st.Protocol == 2 {
				return nil, fmt.Errorf("%w: unknown kid %q", envelope.ErrInvalid, kid)
			}
		}
	}
	if kid != accountFpr {
		return nil, fmt.Errorf("%w: unknown kid %q", envelope.ErrInvalid, kid)
	}
	kp, err := id.Keypair(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient key unavailable", envelope.ErrInvalid)
	}
	return kp, nil
}
