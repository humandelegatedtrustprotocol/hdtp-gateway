package public

// HDTP 1.0 receiving (HDTP §13.3, §6.1, §5.3, §14.3, §14.4): a `v: 2`
// envelope is decided by the library's pure Decide over the state this node
// supplies, and the effects it returns are applied here — the pin that
// follows a newer leaf or a new address, the former endpoint, the pending
// address the owner must answer, the event the owner is shown. The library
// holds no state and never touches the store; this file is the seam.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/envelope"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// ErrChainRequired is HDTP §13.2's uniform answer to a small-form envelope the
// receiver cannot verify against a leaf it holds: unknown, blocked, expired,
// or a bad signature — one answer, so nothing leaks. It travels in plaintext
// and is charged to the guest budget (§14.5).
var ErrChainRequired = errors.New("chain_required")

// CertificateRenewed is HDTP §14.4: an envelope sealed to a key this endpoint
// once held for the identity and holds no longer is answered, in plaintext,
// with the identity's current chain.
type CertificateRenewed struct{ Chain [][]byte }

func (e *CertificateRenewed) Error() string { return "certificate_renewed" }

// TierPendingAddress is the seed's fourth outcome: a pinned root at a new
// address under `ask`, or one returned after a removal. It is not a tier the
// pool knows; the call answers `{"status": "pending"}` and nothing runs.
const TierPendingAddress policy.Tier = "pending_new_address"

// RecipientState is everything Decide reads about this account, supplied per call so
// a setting the owner changes takes effect without a restart.
type RecipientState struct {
	// HasRoot is whether the wallet has issued this identity a leaf: until it has, there is no
	// chain to speak under and nothing sealed can be opened (HDTP §2).
	HasRoot        bool
	Endpoint       string
	AcceptNewHosts string
	Chain          [][]byte           // [current leaf, root]
	Keys           []identity.LeafKey // current first, superseded until notAfter
	Former         []string           // kids once held (§14.4)
	SiblingKids    []string           // kids held for other identities on this origin
}

// current is the leaf key that signs and seals today.
func (s *RecipientState) current() *identity.LeafKey {
	for i := range s.Keys {
		if s.Keys[i].Current {
			return &s.Keys[i]
		}
	}
	return nil
}

// peeked is the proof a sealed call's plaintext carries, read before Decide: the chain of the full
// form, or the leaf fingerprint the small form names. Nothing read here is trusted; it only says
// which pins Decide is handed (pinsFor), and Decide opens the envelope again and verifies it.
type peeked struct {
	Chain []string `json:"chain"`
	Leaf  string   `json:"leaf"`
}

// opener is the held key an envelope's header names and the suite it is sealed in, when this node
// opens it: a header that is not base64url, an unknown kid, a key past its date or a suite nobody
// knows is nil — an envelope nothing here opens.
func opener(now time.Time, e *hdtpidentity.Envelope, st *RecipientState) (*identity.LeafKey, string) {
	var header struct {
		Kid   string `json:"kid"`
		Suite string `json:"suite"`
	}
	protected, err := hdtpidentity.DecodeB64url(e.Protected)
	if err != nil || json.Unmarshal(protected, &header) != nil || !hdtpidentity.SuiteKnown(header.Suite) {
		return nil, ""
	}
	for i := range st.Keys {
		if k := &st.Keys[i]; k.Kid == header.Kid && (k.Current || !now.After(k.NotAfter)) {
			return k, header.Suite
		}
	}
	return nil, ""
}

// errOpened marks a refusal of an envelope this node OPENED (one of its keys is the one the header
// named, so HPKE ran on it) and that proved no caller: the wrapper spends the guest total for it
// (sealed.go), so a flood the open cannot place drains it and meets the check before the open. The
// refusal's code is unchanged: errOpened is none of the errors Code reads.
var errOpened = errors.New("the envelope was opened")

// openedIf marks err as a refusal of an opened envelope when it was one.
func openedIf(opened bool, err error) error {
	if !opened {
		return err
	}
	return fmt.Errorf("%w (%w)", err, errOpened)
}

// peekProof opens e with the key Decide would pick (the kid's, current or not yet expired) and reads
// its proof. The zero value when it cannot: a member that is not base64url, an unknown kid, a suite
// it does not know, a ciphertext that does not open, a plaintext that is not JSON. One extra HPKE
// open per envelope buys handing Decide a few pins instead of every contact.
func peekProof(now time.Time, e *hdtpidentity.Envelope, st *RecipientState) peeked {
	var none peeked
	aad, errAAD := hdtpidentity.DecodeB64url(e.Protected)
	enc, errEnc := hdtpidentity.DecodeB64url(e.Enc)
	ct, errCt := hdtpidentity.DecodeB64url(e.Ct)
	if errAAD != nil || errEnc != nil || errCt != nil {
		return none
	}
	if k, suite := opener(now, e, st); k != nil && k.Lib != nil {
		priv := k.Lib
		// The recipient's public key as its leaf holds it (the identity core 0.4.0): the open takes it
		// rather than deriving it from the private key on every call.
		leaf, err := hdtpidentity.Parse(k.Leaf)
		if err != nil {
			return none
		}
		plaintext, err := hdtpidentity.Open(suite, priv, leaf.PublicKey, []byte(hdtpidentity.InfoV2), aad, enc, ct)
		if err != nil {
			return none
		}
		var p peeked
		if json.Unmarshal(plaintext, &p) != nil {
			return none
		}
		return p
	}
	return none
}

// pinsFor is the contacts Decide needs for an envelope whose proof is p, and no others. Decide reads
// pins three ways (hdtp-identity envelope.go): the pin of the root a chain proves (its tier, a
// renewal, a new address), the pins at the address the chain's leaf names (the address claim of
// HDTP sec. 5.2), and the pin holding the leaf a small form names (pinHolding). Until 2026-09-28 it
// was handed every contact, so a call cost the node time in proportion to how many the account held
// (decide_candidates_test.go holds the decisions equal). A proof that cannot be read, or a chain
// that does not parse, gets no pins: Decide refuses such an envelope whatever it is handed.
func (id *Identifier) pinsFor(ctx context.Context, accountID string, p peeked) ([]store.Contact, error) {
	switch {
	case len(p.Chain) == 2:
		leafDER, errLeaf := hdtpidentity.DecodeB64url(p.Chain[0])
		rootDER, errRoot := hdtpidentity.DecodeB64url(p.Chain[1])
		if errLeaf != nil || errRoot != nil {
			return nil, nil
		}
		leaf, errLeaf := hdtpidentity.Parse(leafDER)
		root, errRoot := hdtpidentity.Parse(rootDER)
		if errLeaf != nil || errRoot != nil {
			return nil, nil
		}
		endpoint := ""
		if len(leaf.URIs) > 0 {
			endpoint = leaf.URIs[0]
		}
		return id.Store.PinCandidates(ctx, accountID, hdtpidentity.FingerprintOf(root), endpoint, "")
	case p.Leaf != "":
		return id.Store.PinCandidates(ctx, accountID, "", "", p.Leaf)
	}
	return nil, nil
}

// nodeState builds Decide's input from the store and the supplied state, with the pins the
// envelope's proof could concern.
func (id *Identifier) nodeState(ctx context.Context, accountID string, st *RecipientState, p peeked) (hdtpidentity.NodeState, error) {
	ns := hdtpidentity.NodeState{
		Endpoint: st.Endpoint, AcceptNewHosts: st.AcceptNewHosts, Former: st.Former, SiblingKids: st.SiblingKids,
	}
	if ns.AcceptNewHosts == "" {
		ns.AcceptNewHosts = "auto"
	}
	for _, c := range st.Chain {
		ns.Chain = append(ns.Chain, hdtpidentity.B64url(c))
	}
	for _, k := range st.Keys {
		if len(k.PKCS8) == 0 {
			return ns, fmt.Errorf("the held key %s is not open", k.Kid)
		}
		ns.Keys = append(ns.Keys, hdtpidentity.HeldKey{Kid: k.Kid, Leaf: hdtpidentity.B64url(k.Leaf), PKCS8: hdtpidentity.B64url(k.PKCS8), Current: k.Current})
	}
	contacts, err := id.pinsFor(ctx, accountID, p)
	if err != nil {
		return ns, err
	}
	ns.Pins = pinsOf(contacts)
	tombs, err := id.Store.ListTombstones(ctx, accountID)
	if err != nil {
		return ns, err
	}
	for _, t := range tombs {
		ns.Tombstones = append(ns.Tombstones, hdtpidentity.TombstoneRec{Root: t.Root, Leaf: hdtpidentity.B64url(t.Leaf), At: time.Unix(t.At, 0).UTC().Format(time.RFC3339)})
	}
	formers, err := id.Store.ListFormerEndpoints(ctx, accountID)
	if err != nil {
		return ns, err
	}
	for _, f := range formers {
		ns.FormerEndpoints = append(ns.FormerEndpoints, hdtpidentity.FormerEndpoint{Root: f.Root, Endpoint: f.Endpoint, At: time.Unix(f.At, 0).UTC().Format(time.RFC3339)})
	}
	return ns, nil
}

// pinStates are the states a pin has (CONTRACT `Pin`): the rows handed to Decide, as BatonDeck's
// `pinsOf` hands them (gateway/src/identity/wire.ts), so both hosts decide one envelope alike.
// the identity core 0.4.2 refuses any other state as unreadable host state, where 0.4.1 read it as
// active. A request the owner has not answered (`pending_in`) is therefore NO pin: its requester is
// the guest SPEC §5.4 says it is — its small form names a leaf nobody pinned and is refused
// `chain_required`, its chain form is decided as a stranger's (a repeated `request_contact` is then
// `pending_approval`, tools.go), the audit row is a guest's (actorOf), and the effects Decide
// returns for an active pin — the newer leaf a chain carries, a new address under `auto` — reach
// no row the owner has not approved. The owner decided it on 2026-09-30, taking the cloud's side;
// TestAPendingRequestIsHandedToDecideWithNoPin holds it.
var pinStates = map[string]bool{"active": true, "pending_out": true, "blocked": true}

// UnknownContactState says whether a contact row's status is one this node does not know: neither
// a state a pin has (pinStates) nor a request awaiting the owner (`pending_in`). pinsOf hands
// Decide no pin for such a row, exactly as for a request — where the identity core 0.4.2 would refuse
// the state as unreadable and the owner would be told on the call (`identity_state_unreadable`).
// The schema admits no such row (the schema's CHECK holds a contact's status to the four, on
// both engines), so one is a hand-edited store's or a later binary's; the walk of
// internal/storecheck counts and names each, so the owner is told at `serve` and by `check store`
// rather than never. TestARowInAStateThisNodeDoesNotKnowIsHandedToDecideAsNoPin holds the two
// readings to each other.
func UnknownContactState(status string) bool { return !pinStates[status] && status != "pending_in" }

// pinsOf is Decide's pins, from contact rows: every row that holds a leaf, in a state the core
// reads (pinStates); the others — a request awaiting the owner, and a row in a state this node does
// not know (UnknownContactState) — are left out.
func pinsOf(contacts []store.Contact) []hdtpidentity.Pin {
	var pins []hdtpidentity.Pin
	for _, c := range contacts {
		if len(c.Leaf) > 0 && pinStates[c.Status] {
			// The pin says which leaf it holds (HDTP 1.0, CONTRACT §5), so a small-form envelope —
			// from a sender who has proved nothing yet — is matched on a string and ONE pinned leaf is
			// parsed, not every contact's. The row keeps the leaf's key beside the leaf (the one
			// statement that writes `leaf` writes `spki` with it), and the core holds the claim to the
			// certificate: a row where the two disagree is unreadable state, and is said.
			pin := hdtpidentity.Pin{Root: c.Fingerprint, Endpoint: c.Endpoint, Leaf: hdtpidentity.B64url(c.Leaf), State: c.Status}
			if len(c.SPKI) > 0 {
				pin.LeafFingerprint = hdtpidentity.Fingerprint(c.SPKI)
			}
			pins = append(pins, pin)
		}
	}
	return pins
}

// signer is the leaf a `pending_approval` was decided under, and the form that named it.
type signer struct {
	root string
	spki []byte
	leaf []byte
	form string
}

// signerOf is who signed an envelope Decide answered `pending_approval`, read from the proof the node
// peeked (the same plaintext Decide opened) and the pins it handed Decide. The identity core 0.4.1 answers
// that code with nothing but the code, and only after the signature verified (envelope.go, Decide):
// in the full form under the chain's leaf, once the chain validated; in the small form under the
// pinned leaf the envelope names. So the key is that leaf's, and the refusal can be sealed to it.
//
// The pin the answer was decided for must be `pending_out` — the one state Decide answers this for —
// or no signer is named and the refusal goes out as itself (sealBackErr): the node never seals to a
// key other than the one Decide verified.
func signerOf(p peeked, pins []hdtpidentity.Pin) (signer, bool) {
	switch {
	case len(p.Chain) == 2:
		leafDER, errLeaf := hdtpidentity.DecodeB64url(p.Chain[0])
		rootDER, errRoot := hdtpidentity.DecodeB64url(p.Chain[1])
		if errLeaf != nil || errRoot != nil {
			return signer{}, false
		}
		leaf, errLeaf := hdtpidentity.Parse(leafDER)
		rootCert, errRoot := hdtpidentity.Parse(rootDER)
		if errLeaf != nil || errRoot != nil {
			return signer{}, false
		}
		root := hdtpidentity.FingerprintOf(rootCert)
		for _, pin := range pins {
			if pin.Root == root {
				if pin.State != "pending_out" {
					return signer{}, false
				}
				return signer{root: root, spki: leaf.SPKI, leaf: leafDER, form: "chain"}, true
			}
		}
	case p.Leaf != "":
		// pinHolding's reading (hdtp-identity envelope.go): the first pin that is not blocked, whose
		// column does not name another leaf, and whose leaf's own fingerprint is the one named. The
		// match is on the fingerprint computed from the leaf, not on the column.
		for _, pin := range pins {
			if pin.State == "blocked" || (pin.LeafFingerprint != "" && pin.LeafFingerprint != p.Leaf) {
				continue
			}
			leafDER, err := hdtpidentity.DecodeB64url(pin.Leaf)
			if err != nil {
				continue
			}
			leaf, err := hdtpidentity.Parse(leafDER)
			if err != nil || hdtpidentity.Fingerprint(leaf.SPKI) != p.Leaf {
				continue
			}
			if pin.State != "pending_out" {
				return signer{}, false
			}
			return signer{root: pin.Root, spki: leaf.SPKI, leaf: leafDER, form: "leaf"}, true
		}
	}
	return signer{}, false
}

// decideEnvelope is the `v: 2` half of OpenSealed.
func (id *Identifier) decideEnvelope(ctx context.Context, accountID string, tf TransportFacts, e *hdtpidentity.Envelope) (*EnvelopeFacts, error) {
	if id.RecipientState == nil {
		return nil, fmt.Errorf("%w: this identity does not speak 2.0", envelope.ErrInvalid)
	}
	st, err := id.RecipientState(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	if st == nil || !st.HasRoot {
		return nil, fmt.Errorf("%w: this identity has no certificate yet", envelope.ErrInvalid)
	}
	// The members go to the library exactly as they arrived: it holds each to its one spelling
	// (HDTP §13.1), which a decode and re-encode here would launder.
	now := id.now()
	// Whether this envelope is OPENED here: a refusal of one that proves no caller spends the guest
	// total (errOpened).
	key, _ := opener(now, e, st)
	opened := key != nil
	proof := peekProof(now, e, st)
	ns, err := id.nodeState(ctx, accountID, st, proof)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
	}
	d, err := hdtpidentity.Decide(now, *e, ns)
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
		return nil, openedIf(opened, fmt.Errorf("%w: %s", envelope.ErrInvalid, why))
	case "chain_required":
		return nil, ErrChainRequired
	case "certificate_renewed":
		// The chain is this node's own — ns.Chain, as nodeState encoded it — handed back by Decide.
		// A member that does not read is a row of this node's state that would not, told as
		// Decide's own error is above.
		var chain [][]byte
		if data, ok := d.Result["data"].(map[string]any); ok {
			if cs, ok := data["chain"].([]any); ok {
				for _, c := range cs {
					s, ok := c.(string)
					if !ok {
						continue
					}
					der, err := hdtpidentity.DecodeB64url(s)
					if err != nil {
						id.audit("identity_state_unreadable", "account:"+accountID+" why:"+err.Error(), "error")
						return nil, fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)
					}
					chain = append(chain, der)
				}
			}
		}
		return nil, openedIf(opened, &CertificateRenewed{Chain: chain})
	case "pending_approval":
		// A pin in `pending_out` calling something other than contact_accepted or
		// contact_rejected, or a listing of them (a sealed tools/list answers at the
		// pending tier): the contact request has not been answered yet, so
		// nothing else runs. (A new address the owner has not approved is the
		// `pending_new_address` tier below, not this.) The refusal is sealed to the leaf that
		// signed (HDTP §13.2), read by signerOf, and charged to the root it proves; nothing is
		// dispatched and no tier is earned (the facts carry none, so the audit row's actor is a guest).
		//
		// The effects Decide returns beside it are NOT applied: in the full form they can carry a
		// pending contact's newer leaf, or its new address under `auto` (hdtp-identity envelope.go),
		// and they are dropped (docs/release/port-parity-2026-09-29.md, §5).
		facts := &EnvelopeFacts{Refusal: "pending_approval", state: st}
		if sg, ok := signerOf(proof, ns.Pins); ok {
			// Decide read `protected` in its one spelling and decided on it, so it reads here too.
			var h envelope.Header
			protected, _ := hdtpidentity.DecodeB64url(e.Protected)
			_ = json.Unmarshal(protected, &h)
			// From is the root the signature proved, as an `ok` decision names it: the budget charges
			// the call to that root (node.chargeOf pays a proven pending_out contact's guest bucket at
			// its address, without the guest total), and the seal records what that contact has seen.
			facts.Header, facts.From, facts.SPKI, facts.Leaf, facts.Form = h, sg.root, sg.spki, sg.leaf, sg.form
		}
		return facts, nil
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
	leafB64, _ := d.Result["leaf"].(string)
	leafDER, err := hdtpidentity.DecodeB64url(leafB64)
	if err != nil {
		return nil, fmt.Errorf("%w: decided leaf unreadable", envelope.ErrInvalid)
	}
	leaf, err := hdtpidentity.Parse(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w: decided leaf unreadable", envelope.ErrInvalid)
	}
	params, _ := json.Marshal(d.Result["params"])
	if d.Result["params"] == nil {
		params = nil
	}
	// Decide has read `protected` in its one spelling and verified the signature over it, so it
	// reads here too, to the same bytes.
	var h envelope.Header
	protected, _ := hdtpidentity.DecodeB64url(e.Protected)
	_ = json.Unmarshal(protected, &h)
	facts := &EnvelopeFacts{
		Header: h, From: root, SPKI: leaf.SPKI, Payload: Payload{Method: method, Params: params},
		Tier: policy.Tier(tier), Endpoint: endpoint, Leaf: leafDER, Form: form, Why: why, state: st,
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
		return nil, openedIf(opened, fmt.Errorf("%w: client certificate key does not match the envelope's leaf", envelope.ErrInvalid))
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
			leafB64, _ := ef["leaf"].(string)
			leafDER, err := hdtpidentity.DecodeB64url(leafB64)
			if err != nil {
				return err
			}
			leaf, err := hdtpidentity.Parse(leafDER)
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
			leafB64, _ := ef["leaf"].(string)
			leafDER, err := hdtpidentity.DecodeB64url(leafB64)
			if err != nil {
				return err
			}
			// No root certificate on this path: the chain the sender carried is inside
			// the ciphertext, and only the library's Decide ever sees it. The pending
			// row keeps the leaf; the cert arrives if that host connects with a client
			// certificate.
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
// checks of HDTP §14.3 and §5.3 have run — the same outcomes the sealed path
// reaches through Decide, so a chain presented at the TLS layer can do nothing
// an envelope carrying it could not. Fingerprint is the identity the per-caller
// server is composed for: the root when the pin
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
// effects (decide.go apply): a newer leaf at the pinned endpoint replaces
// it; another endpoint is §5.3 — re-pinned with the former endpoint and the
// owner's event under `auto`, parked as a pending address under `ask`, and
// and under `ask` after a removal within the tombstone window. It runs once per
// request, before the per-caller server is composed,
// and its result is what PoolGate enforces on every call.
func (id *Identifier) ResolveTransport(ctx context.Context, tf TransportFacts) TransportCaller {
	root := tf.ClientCertFingerprint
	if !tf.ChainProven() || root == "" {
		return TransportCaller{Fingerprint: root}
	}
	leaf, err := hdtpidentity.Parse(tf.ClientLeaf)
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
	// This is where a pin without its root certificate gets one:
	// the chain that just validated carries the root, and a pin made over a sealed
	// call never saw it. Never overwrites — the root of a pin cannot change — and a
	// failure is not fatal to the request, which is about the caller, not the column.
	if len(c.RootCert) == 0 && len(tf.ClientRoot) > 0 {
		if err := id.Store.SetContactRootCert(ctx, id.AccountID, root, tf.ClientRoot); err != nil {
			id.audit("contact_root_cert", "account:"+id.AccountID+" contact:"+root, "error")
		}
	}
	cmp, err := hdtpidentity.CompareLeaves(c.Leaf, tf.ClientLeaf)
	if err != nil || cmp == "superseded" || cmp == "conflict" {
		id.audit("identity_gate", "account:"+id.AccountID+" contact:"+root, "superseded_leaf")
		return TransportCaller{Demote: true}
	}
	if endpoint != c.Endpoint {
		policy := "auto"
		if id.RecipientState != nil {
			if st, serr := id.RecipientState(ctx); serr == nil && st != nil && st.AcceptNewHosts != "" {
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
