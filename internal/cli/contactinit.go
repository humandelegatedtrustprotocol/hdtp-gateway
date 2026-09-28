package cli

// Owner-initiated contact establishment (SPEC §9: `none --> pending_out`), and the calls that
// tell a peer how the owner answered its request (`contact_accepted`, `contact_rejected`).
//
// The inbound half — a guest calling `redeem_invite` or `request_contact` on us —
// was built from the start. This is the outbound half, which was specified and
// never implemented: nothing could make THIS node place that call, so a node could
// only ever hold as contacts the agents that had called in (E16).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/node"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// newContactInitiator builds the one initiator every surface uses.
//
// It was constructed by hand in four places, and each copy had to remember every
// field: the first one to forget `setPermissions` would silently stop granting
// what the owner chose. One constructor means the portal and the owner MCP cannot
// drift apart, which is the whole point of SPEC §8.4's parity.
func newContactInitiator(st store.Store, nd *node.Node,
	auditFn func(action, resource, outcome string)) *contactInitiator {
	return &contactInitiator{
		manager:  contactsManager(st, nd),
		card:     nd.Card,
		outbound: nd.OutboundClient,
		request:  nd.RequestContact,
		audit:    auditFn,
		contact: func(ctx context.Context, accountID, fpr string) (store.Contact, error) {
			return st.GetContact(ctx, accountID, fpr)
		},
		setPermissions: func(ctx context.Context, accountID, fpr string, perms []string, preset string) error {
			return st.UpdateContactPermissions(ctx, accountID, fpr, perms, preset)
		},
	}
}

// maxOfferBytes caps the invite landing document. It is fetched from a host we
// have not yet pinned, so it is untrusted input in the strongest sense.
const maxOfferBytes = 64 << 10

// inviteOffer is the landing page's machine view (SPEC §9.2): the issuer's card, the
// `[leaf, root]` chain that proves it, the card's signature, and the leaf's public key.
//
// `Chain` is the 2.0 addition and it is the load-bearing one. A 1.x offer was a card naming a
// KEY plus that key, so the three fields above were the whole proof. A 2.0 card carries a
// certificate, and what a peer pins is the ROOT that signed it — which is inside the chain and
// nowhere else in this document.
type inviteOffer struct {
	Card    string   `json:"card"`
	CardSig string   `json:"card_sig"`
	Chain   []string `json:"chain"`
}

// splitInviteURL separates an invite link into the origin and its token.
func splitInviteURL(raw string) (origin, token string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", fmt.Errorf("an invite link is an https:// URL")
	}
	i := strings.LastIndex(u.Path, "/i/")
	if i < 0 {
		return "", "", fmt.Errorf("that does not look like an invite link (no /i/<token>)")
	}
	token = strings.Trim(u.Path[i+len("/i/"):], "/")
	if token == "" {
		return "", "", fmt.Errorf("the invite link carries no token")
	}
	return u.Scheme + "://" + u.Host, token, nil
}

// fetchOffer reads the landing page's machine view.
//
// The TLS here is deliberately unverified, and that is not a shortcut: we do not
// yet know the peer's key — learning it is the point — and the link may be served
// through an edge that terminates TLS with a certificate that is not the node's.
// Nothing from this response is trusted on the strength of the transport. What
// makes it safe is the checks in verifyOffer plus the fact that the redemption
// call that follows is PINNED to the key this document claims: a tampered
// document can only send us to a peer that holds the key it names, which is the
// bearer-token trust model SPEC §9.2 already states for invite links.
func fetchOffer(ctx context.Context, hc *http.Client, inviteURL string) (inviteOffer, error) {
	var off inviteOffer
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, inviteURL, nil)
	if err != nil {
		return off, err
	}
	req.Header.Set("Accept", "application/pact-invite+json")
	res, err := hc.Do(req)
	if err != nil {
		return off, fmt.Errorf("could not reach the invite link: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return off, fmt.Errorf("the invite link answered HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxOfferBytes))
	if err != nil {
		return off, err
	}
	if err := json.Unmarshal(body, &off); err != nil {
		return off, fmt.Errorf("the invite link did not return a machine-readable card")
	}
	return off, nil
}

// verifyOffer turns an untrusted document into an identity we are willing to pin.
//
// A card carries a certificate, and the identity, the address and the key are all read from
// inside it — none is a property of the card. This is the path `pact-gateway contact init
// <invite-url>` takes when somebody sends a person an invite link.
//
// Four checks, each load-bearing, in the order a receiver applies them (SPEC §14.2, §9.2):
//
//  1. the card decodes and its certificate parses, which is what `ValidateInbound` does — and
//     which fills the ROOT as the identity and the leaf's subjectAltName as the address;
//  2. the chain validates: two certificates, a self-signed root, a leaf it signed, in date,
//     naming the address the card names. Without this the "root" is whatever the leaf claims
//     its issuer is, and anybody can claim anything;
//  3. the card's certificate IS the chain's leaf, byte for byte, so the card and the chain are
//     one peer's documents rather than two assembled into a plausible pair; and
//  4. that leaf's key signed the card bytes — which is what makes the sealed redemption that
//     follows reach the peer this document describes and nobody else.
func verifyOffer(off inviteOffer) (card contacts.Card, spki, rootCert []byte, err error) {
	if len(off.Card) > maxOfferBytes {
		return card, nil, nil, fmt.Errorf("the card is implausibly large")
	}
	card, err = contacts.ValidateInbound(off.Card)
	if err != nil {
		return card, nil, nil, fmt.Errorf("the invite's card: %w", err)
	}
	if len(off.Chain) != 2 {
		return card, nil, nil, fmt.Errorf("the invite offer carries no [leaf, root] chain, so there is no root to pin (SPEC §9.2)")
	}
	chain := [][]byte{pactidentity.FromB64url(off.Chain[0]), pactidentity.FromB64url(off.Chain[1])}
	v := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: time.Now(), ExpectedEndpoint: card.Endpoint})
	if !v.OK {
		return card, nil, nil, fmt.Errorf("the invite's chain is refused by rule %d: %s", v.Rule, v.Reason)
	}
	if !bytes.Equal(chain[0], card.Cert) {
		return card, nil, nil, fmt.Errorf("the invite's chain does not carry the certificate its card does")
	}
	if v.RootFingerprint != card.Key {
		return card, nil, nil, fmt.Errorf("the invite's chain is signed by %s, not the root the card names", v.RootFingerprint)
	}
	// The key to seal to is the validated leaf's, read from the chain and from nowhere else.
	// An offer used to have to carry it a second time as `spki` and was refused without it —
	// PACT 1.2's "SPKI distribution", from when a card held only a key's hash. §4 gives a landing
	// three members and that is not one of them, so demanding it made every invite from a
	// spec-exact issuer unredeemable here.
	spki = v.LeafKey.SPKI
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return card, nil, nil, fmt.Errorf("the invite's key is unreadable")
	}
	sig, err := base64.RawURLEncoding.DecodeString(off.CardSig)
	if err != nil || len(sig) == 0 {
		return card, nil, nil, fmt.Errorf("the invite's card is not signed")
	}
	if !identity.VerifyBytes(pub, []byte(off.Card), sig) {
		return card, nil, nil, fmt.Errorf("the invite's card signature does not verify")
	}
	return card, spki, chain[1], nil
}

// peerOfCard is the peer a validated 2.0 card describes: pinned by its ROOT, called at the
// address its leaf names, and sealed to that leaf's key. The root and the leaf are what let
// `outbound.Client` speak at all — it refuses a peer it holds neither for (`Peer.Known`).
func peerOfCard(card contacts.Card) outbound.Peer {
	return outbound.Peer{
		Endpoint: card.Endpoint, Seal: card.Seal,
		Root: card.Key, Leaf: card.Cert,
	}
}

// offerClient fetches invite landings.
//
// Chain verification is OFF, and the reason is structural: in direct mode the
// public surface serves an identity-key self-signed certificate (SPEC §3.8), so
// there is no chain for WebPKI to validate and no pin yet either — learning the
// key is the point of this fetch.
//
// What that costs is worth stating rather than burying: the transport
// authenticates nothing, so a network attacker who can intercept this fetch can
// serve a wholly self-consistent offer of their own, and verifyOffer will accept
// it because it IS internally consistent. This is the documented "card trust is
// channel trust" trade-off (SPEC §13) reaching its sharpest point. Confirming the
// fingerprint out of band is what closes it. See docs/threat-model.md, A4.
func offerClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			// #nosec G402 -- self-signed identity certificate; see the doc comment above
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

// contactInitiator holds what the outbound half needs, injected rather than
// reached for, so the whole flow can be tested against a real peer node without
// standing up a portal.
type contactInitiator struct {
	// setPermissions records what WE grant THEM (the node's preset bundles).
	setPermissions func(ctx context.Context, accountID, fpr string, perms []string, preset string) error
	// contact reads a stored contact; nil falls back to the manager's store.
	contact  func(ctx context.Context, accountID, fpr string) (store.Contact, error)
	manager  *contacts.Manager
	card     func(ctx context.Context, accountID string) (string, error)
	outbound func(accountID string) (*outbound.Client, error)
	// request sends request_contact: node.RequestContact, which the move campaign's fallback
	// calls too.
	request func(ctx context.Context, accountID string, peer outbound.Peer, note, callID string) error
	audit   func(action, resource, outcome string)
	// httpClient fetches invite landings; nil uses offerClient().
	httpClient func() *http.Client
}

func (ci *contactInitiator) offerHTTP() *http.Client {
	if ci.httpClient != nil {
		return ci.httpClient()
	}
	return offerClient()
}

// addContactResult is what the owner sees back.
type addContactResult struct {
	Fingerprint string   `json:"fingerprint"`
	DisplayName string   `json:"display_name"`
	Status      string   `json:"status"` // active | pending_out
	Permissions []string `json:"permissions,omitempty"`
}

// Add is the owner reaching out, by either of the two paths SPEC §9 specifies: an invite link
// they were sent (RedeemInvite), or a card they hold out of band (RequestContact). It is the one
// function behind the owner MCP's add_contact and the portal's People page, so the two surfaces
// cannot disagree about which path a request takes.
func (ci *contactInitiator) Add(ctx context.Context, accountID, inviteURL, card, note, grant string) (addContactResult, error) {
	switch {
	case inviteURL != "" && card != "":
		return addContactResult{}, fmt.Errorf("an invite link or a card, not both")
	case inviteURL != "":
		return ci.RedeemInvite(ctx, accountID, inviteURL, grant)
	case card != "":
		return ci.RequestContact(ctx, accountID, card, note)
	}
	return addContactResult{}, fmt.Errorf("an invite link or their card is needed")
}

// RedeemInvite is the owner pasting somebody's invite link.
//
// `grant` is what WE give THEM on OUR node, and it is separate from what their
// invite gave us on purpose: an invite must not choose its own privileges on the
// machine that redeems it. But it must be ASKED for, because granting nothing
// leaves the relationship one-way — they are a contact who can reach nothing, and
// every message they send is refused `permission_denied` forever.
func (ci *contactInitiator) RedeemInvite(ctx context.Context, accountID, inviteURL, grant string) (addContactResult, error) {
	var out addContactResult
	_, token, err := splitInviteURL(inviteURL)
	if err != nil {
		return out, err
	}
	off, err := fetchOffer(ctx, ci.offerHTTP(), inviteURL)
	if err != nil {
		return out, err
	}
	peerCard, spki, peerRootCert, err := verifyOffer(off)
	if err != nil {
		ci.audit("contact_initiate", "account:"+accountID+" url:"+inviteURL, "refused")
		return out, err
	}
	ourCard, err := ci.card(ctx, accountID)
	if err != nil {
		return out, err
	}
	// Our own invite: the offer's root is this identity's. A person does not become their own
	// contact (the cloud refuses the same redemption); the receiving side refuses it too (a guest's
	// endpoint never equals the receiver's own, §14.5), but that refusal came back as a tool error
	// the answer below used to read as "pending", and the owner was left holding themselves
	// pending_out (harness S21).
	if ours, err := contacts.ValidateInbound(ourCard); err == nil && ours.Key == peerCard.Key {
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "own_invite")
		return out, fmt.Errorf("that is this identity's own invite")
	}
	client, err := ci.outbound(accountID)
	if err != nil {
		return out, err
	}
	peer := peerOfCard(peerCard)
	res, err := client.Call(ctx, peer, "redeem_invite",
		map[string]any{"token": token, "card": ourCard}, newCallID())
	if err != nil {
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "unreachable")
		return out, fmt.Errorf("the peer refused the redemption: %w", err)
	}
	// A refusal is an answer with isError and its code (PACT §12): nothing was redeemed, so
	// nothing is recorded. It used to fall through to decodeRedeemAnswer, whose empty status
	// recorded the peer pending_out.
	if res.IsError {
		code := refusalCodeOf(res)
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "refused")
		return out, fmt.Errorf("the peer refused the redemption: %s", code)
	}
	answer := decodeRedeemAnswer(res)
	// Record only AFTER the peer accepted the redemption: a contact row written
	// on a failed call would leave a pin for a relationship that does not exist.
	if err := ci.manager.Initiated(ctx, accountID, peerCard.Key, off.Card, spki,
		answer.Status == "accepted", answer.Permissions); err != nil {
		return out, err
	}
	// The pin keeps the ROOT's certificate, not just its fingerprint (migration 0029):
	// this is the one moment it is in hand, since the offer's chain carried it and a
	// later sealed call will not. Not fatal - the pin is the thing that had to happen.
	if err := ci.manager.Store.SetContactRootCert(ctx, accountID, peerCard.Key, peerRootCert); err != nil {
		ci.audit("contact_root_cert", "account:"+accountID+" peer:"+peerCard.Key, "error")
	}
	status := "pending_out"
	if answer.Status == "accepted" {
		status = "active"
	}
	// What we grant them. Accepting somebody's invite means agreeing to talk, so
	// the DEFAULT is that they can send messages — a contact who cannot reply is
	// not a contact. `none` is how an owner deliberately grants nothing.
	if grant == "" {
		grant = "basic"
	}
	if grant == "none" {
		grant = ""
	}
	if perms, ok := contacts.LoadPresets(ctx, ci.manager.Store)[grant]; ok && ci.setPermissions != nil {
		if err := ci.setPermissions(ctx, accountID, peerCard.Key, perms, grant); err != nil {
			ci.audit("contact_permissions", "account:"+accountID+" peer:"+peerCard.Key, "error")
		}
	}
	ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, status)
	return addContactResult{
		Fingerprint: peerCard.Key, DisplayName: peerCard.FN,
		Status: status, Permissions: answer.Permissions,
	}, nil
}

// refusalCodeOf is a tool error's code, or "refused" when its text carries none.
func refusalCodeOf(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && len(tc.Text) <= maxOfferBytes {
			var body struct {
				Code string `json:"code"`
			}
			if json.Unmarshal([]byte(tc.Text), &body) == nil && body.Code != "" {
				return body.Code
			}
		}
	}
	return "refused"
}

// redeemAnswer is `redeem_invite`'s reply (PACT §6.2).
type redeemAnswer struct {
	Status      string   `json:"status"` // accepted | pending
	Permissions []string `json:"permissions,omitempty"`
}

// decodeRedeemAnswer reads the peer's reply, preferring its structured content.
//
// An unreadable reply is NOT treated as acceptance: the contact then lands
// pending_out, which is the safe direction to be wrong in — the owner sees an
// unconfirmed contact rather than one that silently claims to be active.
func decodeRedeemAnswer(res *mcp.CallToolResult) redeemAnswer {
	var out redeemAnswer
	if res == nil {
		return out
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			_ = json.Unmarshal(b, &out)
		}
	}
	if out.Status == "" {
		for _, c := range res.Content {
			tc, ok := c.(*mcp.TextContent)
			if !ok || len(tc.Text) > maxOfferBytes {
				continue
			}
			_ = json.Unmarshal([]byte(tc.Text), &out)
			break
		}
	}
	return out
}

// RequestContact is the other specified path (SPEC §9): the owner has the peer's
// card out of band — a vCard, a QR — and asks to be added, landing pending_out
// here and pending_in for them.
func (ci *contactInitiator) RequestContact(ctx context.Context, accountID, peerCardText, note string) (addContactResult, error) {
	var out addContactResult
	if len(peerCardText) > maxOfferBytes || len(note) > 1024 {
		return out, fmt.Errorf("that card or note is too large")
	}
	// `ValidateInbound`, not `ParseCard`: a 2.0 card's identity and address are inside its
	// certificate, and reading them is the difference between pinning a root and pinning
	// nothing. With `ParseCard` this path refused every real card as having no key.
	peerCard, err := contacts.ValidateInbound(peerCardText)
	if err != nil {
		return out, fmt.Errorf("that card cannot be pinned: %w", err)
	}
	// **The key comes with the card now.** In 1.x a card named a fingerprint and nothing more, so
	// this call went out in plain text and the key was bound on first contact. A 2.0 card carries
	// the certificate, so the key is here — and the request is sealed to it, which is the only way
	// to reach a peer whose card says `X-PACT-SEAL:required`.
	if err := ci.request(ctx, accountID, peerOfCard(peerCard), note, newCallID()); err != nil {
		outcome := "unreachable"
		var refused node.ErrRequestRefused
		if errors.As(err, &refused) {
			outcome = "refused"
		}
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, outcome)
		return out, fmt.Errorf("the request did not land: %w", err)
	}
	if err := ci.manager.InitiatedByFingerprint(ctx, accountID, peerCard.Key, peerCardText); err != nil {
		return out, err
	}
	ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "pending_out")
	return addContactResult{Fingerprint: peerCard.Key, DisplayName: peerCard.FN, Status: "pending_out"}, nil
}

// NotifyApproved tells a peer that their contact request was accepted.
//
// `contact_accepted` — "Tell me my contact request was accepted" — is a
// pending-tier tool on every node's public surface, implemented and mounted from
// the start. NOTHING ever called it. So approving a request moved the contact to
// active locally and the peer was never told: they sat at `pending_out` forever,
// which is precisely what an owner sees as "I accepted them but they still show
// as pending".
//
// Best-effort by design. The approval is a local decision and stands whether or
// not the peer is reachable this second; the caller reports what happened rather
// than pretending it succeeded.
func (ci *contactInitiator) NotifyApproved(ctx context.Context, accountID, peerFpr string, granted []string) error {
	ourCard, err := ci.card(ctx, accountID)
	if err != nil {
		return err
	}
	args := map[string]any{"card": ourCard}
	if len(granted) > 0 {
		// What we granted THEM, so their agent knows what it may call without
		// probing (PACT §6.2).
		args["permissions"] = granted
	}
	return ci.notifyAsker(ctx, accountID, peerFpr, "contact_accepted", args)
}

// NotifyRejected tells a peer that their contact request was declined: `contact_rejected`, the
// other pending-tier tool, which the node served and never sent (review P-13). Without it a
// requester this node rejects waits at `pending_out` for ever; with it their side demotes its
// row to blocked, its record that the approach was declined (PACT §5.1). Best-effort, like the
// approval: the rejection is local and stands whatever they answer.
func (ci *contactInitiator) NotifyRejected(ctx context.Context, accountID, peerFpr string) error {
	return ci.notifyAsker(ctx, accountID, peerFpr, "contact_rejected", map[string]any{})
}

// notifyAsker makes one pending-tier call to a peer whose request this account decided, and
// audits whether it landed under the tool's name.
func (ci *contactInitiator) notifyAsker(ctx context.Context, accountID, peerFpr, tool string, args map[string]any) error {
	c, err := ci.contact(ctx, accountID, peerFpr)
	if err != nil {
		return err
	}
	// The stored PIN, not the card, is the authority on where this contact answers: `update_contact`
	// and a move both write the row, and a card kept from the first exchange can be older than
	// either. It also means a decision reaches a contact whose card this node never parsed.
	if c.Endpoint == "" || len(c.Leaf) == 0 {
		return fmt.Errorf("that contact has no certificate on file, so there is no address to reach it at; add them again from their card")
	}
	client, err := ci.outbound(accountID)
	if err != nil {
		return err
	}
	peer := outbound.Peer{
		Endpoint: c.Endpoint, Seal: "required",
		Root: peerFpr, Leaf: c.Leaf,
	}
	if _, err := client.Call(ctx, peer, tool, args, newCallID()); err != nil {
		ci.audit(tool, "account:"+accountID+" peer:"+peerFpr, "unreachable")
		return err
	}
	ci.audit(tool, "account:"+accountID+" peer:"+peerFpr, "ok")
	return nil
}
