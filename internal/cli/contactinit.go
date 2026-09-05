package cli

// Owner-initiated contact establishment (SPEC §9: `none --> pending_out`).
//
// The inbound half — a guest calling `redeem_invite` or `request_contact` on us —
// was built from the start. This is the outbound half, which was specified and
// never implemented: nothing could make THIS node place that call, so a node could
// only ever hold as contacts the agents that had called in. Relay-assisted
// delivery, whose whole premise is that neither side has an inbound path, could
// therefore never be set up at all (E16).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
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

// inviteOffer is the landing page's machine view (SPEC §9.2): the issuer's card,
// its signature, and the full public key the card's fingerprint stands for.
type inviteOffer struct {
	Card    string `json:"card"`
	CardSig string `json:"card_sig"`
	SPKI    string `json:"spki"`
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

// verifyOffer turns an untrusted document into a key we are willing to pin.
//
// Both checks are load-bearing. The fingerprint check is what makes the pin mean
// anything: without it a tampered document could hand us an attacker's key under
// the peer's name, and every signature check afterwards would pass for the wrong
// party. The signature check proves the card and the key belong together rather
// than having been assembled from two different peers' documents.
func verifyOffer(off inviteOffer) (card contacts.Card, spki []byte, err error) {
	if len(off.Card) > maxOfferBytes {
		return card, nil, fmt.Errorf("the card is implausibly large")
	}
	card, err = contacts.ParseCard(off.Card)
	if err != nil {
		return card, nil, fmt.Errorf("the invite's card does not parse: %w", err)
	}
	if card.Key == "" {
		return card, nil, fmt.Errorf("the invite's card carries no X-PACT-KEY")
	}
	if card.Endpoint == "" {
		return card, nil, fmt.Errorf("the invite's card carries no endpoint to call")
	}
	spki, err = base64.RawURLEncoding.DecodeString(off.SPKI)
	if err != nil || len(spki) == 0 {
		return card, nil, fmt.Errorf("the invite carried no usable public key")
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return card, nil, fmt.Errorf("the invite's key is unreadable")
	}
	fpr, err := identity.Fingerprint(pub)
	if err != nil || fpr != card.Key {
		return card, nil, fmt.Errorf("the invite's key does not match its card fingerprint")
	}
	sig, err := base64.RawURLEncoding.DecodeString(off.CardSig)
	if err != nil || len(sig) == 0 {
		return card, nil, fmt.Errorf("the invite's card is not signed")
	}
	if !identity.VerifyBytes(pub, []byte(off.Card), sig) {
		return card, nil, fmt.Errorf("the invite's card signature does not verify")
	}
	return card, spki, nil
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
	audit    func(action, resource, outcome string)
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

// redeemInviteAs performs the whole owner-initiated redemption for one account.
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
	peerCard, spki, err := verifyOffer(off)
	if err != nil {
		ci.audit("contact_initiate", "account:"+accountID+" url:"+inviteURL, "refused")
		return out, err
	}
	ourCard, err := ci.card(ctx, accountID)
	if err != nil {
		return out, err
	}
	client, err := ci.outbound(accountID)
	if err != nil {
		return out, err
	}
	peer := outbound.Peer{Endpoint: peerCard.Endpoint, Fingerprint: peerCard.Key, Seal: peerCard.Seal}
	res, err := client.Call(ctx, peer, spki, "redeem_invite",
		map[string]any{"token": token, "card": ourCard}, newCallID())
	if err != nil {
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "unreachable")
		return out, fmt.Errorf("the peer refused the redemption: %w", err)
	}
	answer := decodeRedeemAnswer(res)
	// Record only AFTER the peer accepted the redemption: a contact row written
	// on a failed call would leave a pin for a relationship that does not exist.
	if err := ci.manager.Initiated(ctx, accountID, peerCard.Key, off.Card, spki,
		answer.Status == "accepted", answer.Permissions); err != nil {
		return out, err
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
	peerCard, err := contacts.ParseCard(peerCardText)
	if err != nil || peerCard.Key == "" || peerCard.Endpoint == "" {
		return out, fmt.Errorf("that card needs both X-PACT-KEY and X-PACT-ENDPOINT")
	}
	ourCard, err := ci.card(ctx, accountID)
	if err != nil {
		return out, err
	}
	client, err := ci.outbound(accountID)
	if err != nil {
		return out, err
	}
	// No SPKI: a card carries a fingerprint, never a key (SPEC §2). The call is
	// pinned to that fingerprint, and the key itself is bound on first contact.
	peer := outbound.Peer{Endpoint: peerCard.Endpoint, Fingerprint: peerCard.Key, Seal: peerCard.Seal}
	args := map[string]any{"card": ourCard}
	if note != "" {
		args["note"] = note
	}
	if _, err := client.Call(ctx, peer, nil, "request_contact", args, newCallID()); err != nil {
		ci.audit("contact_initiate", "account:"+accountID+" peer:"+peerCard.Key, "unreachable")
		return out, fmt.Errorf("the peer refused the request: %w", err)
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
	c, err := ci.contact(ctx, accountID, peerFpr)
	if err != nil {
		return err
	}
	peerCard, err := contacts.ParseCard(c.Card)
	if err != nil || peerCard.Endpoint == "" {
		return fmt.Errorf("they published no endpoint, so they cannot be told yet")
	}
	ourCard, err := ci.card(ctx, accountID)
	if err != nil {
		return err
	}
	client, err := ci.outbound(accountID)
	if err != nil {
		return err
	}
	peer := outbound.Peer{Endpoint: peerCard.Endpoint, Fingerprint: peerFpr, Seal: peerCard.Seal}
	args := map[string]any{"card": ourCard}
	if len(granted) > 0 {
		// What we granted THEM, so their agent knows what it may call without
		// probing (PACT §6.2).
		args["permissions"] = granted
	}
	if _, err := client.Call(ctx, peer, c.SPKI, "contact_accepted", args, newCallID()); err != nil {
		ci.audit("contact_accepted", "account:"+accountID+" peer:"+peerFpr, "unreachable")
		return err
	}
	ci.audit("contact_accepted", "account:"+accountID+" peer:"+peerFpr, "ok")
	return nil
}
