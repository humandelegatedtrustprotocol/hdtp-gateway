package outbound

// HDTP 1.0 sending (HDTP §13.2, §14.3, §14.4): toward a contact pinned by its
// root, a call is sealed to the pinned leaf's key and carries our chain until
// that contact has seen our current leaf, our leaf's fingerprint after. The
// answer opens against the pin — the chain validates to the root, or the named
// leaf is the one we hold — and a newer leaf riding in it re-pins. Three
// answers make the caller act once and only once: chain_required (resend with
// the chain), certificate_renewed (follow the chain to the pinned root at the
// dialed address, re-pin, re-seal), and an answer that cannot be verified
// (ask get_card, which always carries the chain, re-pin, retry).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// chain is [leaf, root] for a certified key, nil for one the wallet has not issued a leaf to.
func (c *Client) chain() [][]byte {
	if !c.Keypair.HasChain() {
		return nil
	}
	return [][]byte{c.Keypair.Leaf, c.Keypair.Root}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// canSeal reports whether this exchange is a 2.0 one: our identity holds a
// chain and the peer is pinned by its root.
func (c *Client) canSeal(peer Peer) bool { return peer.Known() && c.chain() != nil }

// pinOf is the pin the answer is opened against.
func pinOf(peer Peer) hdtpidentity.Pin {
	return hdtpidentity.Pin{Root: peer.Root, Endpoint: peer.Endpoint, Leaf: hdtpidentity.B64url(peer.Leaf), State: "active"}
}

// plaintextLegal is the set of §12 codes a peer may legitimately answer IN THE
// CLEAR to a sealed call: everything decided before the envelope opened, where
// there is no proven key to seal toward (HDTP §13.2). Past the open there is
// one, and §13.2 requires the answer sealed — so a plaintext `permission_denied`
// is not the peer speaking. It is whatever carried the call, and in edge mode
// something always does.
//
// Believing those was a free hand to the carrier: forge `permission_denied` and
// the owner is shown a contact refusing them; forge `blocked_or_unknown` and a
// working relationship reads as revoked. Neither costs a key.
//
// `unavailable`, `bad_request`, `too_large` and `rate_limited` stay on the list
// because a node can reach them on either side of the open — a disabled account
// and a withheld tool answer the same code — and the caller cannot tell which.
var plaintextLegal = map[string]bool{
	"chain_required":      true,
	"certificate_renewed": true,
	"envelope_invalid":    true,
	"seal_required":       true,
	"seal_not_accepted":   true,
	"identity_required":   true,
	"rate_limited":        true,
	"unavailable":         true,
	"bad_request":         true,
	"too_large":           true,
}

// refusalCode reads the plaintext code a wrapper-level refusal carries.
func refusalCode(res *mcp.CallToolResult) (code string, data map[string]any) {
	if res == nil || len(res.Content) == 0 {
		return "", nil
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return "", nil
	}
	var body struct {
		Code string         `json:"code"`
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal([]byte(tc.Text), &body)
	return body.Code, body.Data
}

// repin records a newer leaf for the peer — learned from a result, a
// certificate_renewed answer, or get_card — and returns the peer to dial next.
func (c *Client) repin(peer Peer, leaf []byte) (Peer, []byte, error) {
	parsed, err := hdtpidentity.Parse(leaf)
	if err != nil {
		return peer, nil, fmt.Errorf("outbound: the new leaf does not parse: %w", err)
	}
	peer.Leaf = leaf
	if c.OnRepin != nil {
		c.OnRepin(peer, leaf, parsed.SPKI)
	}
	return peer, parsed.SPKI, nil
}

// sealedExchange is one 2.0 request and its answer, with the three
// one-time follow-ups of HDTP §13.2 and §14.4 applied.
func (c *Client) sealedExchange(ctx context.Context, peer Peer, method string, params map[string]any, msgID string) ([]byte, *mcp.CallToolResult, error) {
	form := "chain"
	if peer.ChainSeen {
		form = "leaf"
	}
	plain, refusal, err := c.attempt(ctx, peer, method, params, msgID, form)
	var unverifiable *errUnverifiable
	switch {
	case err == nil && refusal == nil:
		return plain, nil, nil
	case refusal != nil:
		code, data := refusalCode(refusal)
		switch code {
		case "chain_required":
			// The peer no longer holds our leaf — a renewal it has not seen, or
			// a pin it lost. Once, with the chain (§13.2).
			if form == "leaf" {
				return c.attempt(ctx, peer, method, params, msgID, "chain")
			}
		case "certificate_renewed":
			// The key we sealed to has been renewed. The chain proves nothing by
			// itself: follow it only to the pinned root at the dialed address,
			// and only forward (§14.4). Once.
			var chain [][]byte
			if cs, ok := data["chain"].([]any); ok {
				for _, s := range cs {
					str, ok := s.(string)
					if !ok {
						continue
					}
					der, err := hdtpidentity.DecodeB64url(str)
					if err != nil {
						return nil, refusal, errors.New("outbound: certificate_renewed not followed: the chain is not base64url")
					}
					chain = append(chain, der)
				}
			}
			ok, why, leaf := hdtpidentity.FollowRenewed(chain, peer.Root, peer.Leaf, peer.Endpoint, c.now())
			if !ok {
				return nil, refusal, fmt.Errorf("outbound: certificate_renewed not followed: %s", why)
			}
			next, _, err := c.repin(peer, leaf)
			if err != nil {
				return nil, refusal, err
			}
			return c.attempt(ctx, next, method, params, msgID, form)
		}
		return nil, refusal, nil
	case errors.As(err, &unverifiable):
		// The answer is signed by a key we do not hold a leaf for. get_card
		// always answers with the chain (§13.2); a chain that validates to the
		// pinned root at the dialed address and is not older than the pin is
		// the peer's current leaf. Once.
		leaf, gerr := c.chainFromGetCard(ctx, peer)
		if gerr != nil {
			return nil, nil, fmt.Errorf("%w; and get_card: %v", err, gerr)
		}
		next, _, rerr := c.repin(peer, leaf)
		if rerr != nil {
			return nil, nil, rerr
		}
		return c.attempt(ctx, next, method, params, msgID, form)
	default:
		return nil, nil, err
	}
}

// errUnverifiable is an answer that opened but could not be verified against
// any leaf this caller holds for the peer.
type errUnverifiable struct{ why string }

func (e *errUnverifiable) Error() string { return "outbound: unverifiable answer: " + e.why }

// errUnattributable is a plaintext refusal that §13.2 says the peer would have
// sealed. Nobody proved they sent it, so it is not reported as the peer's
// answer — the call failed, and the owner is told that rather than told a lie
// about what their contact said.
type errUnattributable struct{ code string }

func (e *errUnattributable) Error() string {
	if e.code == "" {
		return "outbound: the peer answered in plaintext with no code; a sealed call is answered sealed (HDTP §13.2)"
	}
	return "outbound: " + e.code + " arrived in plaintext; §13.2 requires it sealed, so it is not the peer's answer"
}

// attempt seals one request in the given form, sends it, and opens the answer.
func (c *Client) attempt(ctx context.Context, peer Peer, method string, params map[string]any, msgID, form string) ([]byte, *mcp.CallToolResult, error) {
	// Sealed to the key of the leaf we hold for this peer, read from that leaf. It used to arrive
	// as a second argument beside `peer`, and the first thing done with it was to check it was
	// this same key — two copies of one fact, and a plaintext downgrade wherever a caller had
	// only one of them.
	leafKey := mustSPKIOfLeaf(peer.Leaf)
	if len(leafKey) == 0 {
		return nil, nil, fmt.Errorf("outbound: the leaf held for %s does not parse, so there is no key to seal to", peer.name())
	}
	recipient, err := hdtpidentity.ParseSPKI(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("outbound: peer key: %w", err)
	}
	sender, err := identity.ToLib(c.Keypair)
	if err != nil {
		return nil, nil, err
	}
	senderPublic, err := identity.PublicOf(c.Keypair)
	if err != nil {
		return nil, nil, err
	}
	pb := json.RawMessage(`{}`)
	if params != nil {
		if pb, err = json.Marshal(params); err != nil {
			return nil, nil, err
		}
	}
	now := c.now()
	env, err := hdtpidentity.SealRequest(hdtpidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: form, SenderChain: c.chain(),
		Method: method, Params: pb, MsgID: msgID, TS: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("outbound: seal: %w", err)
	}
	wire := map[string]any{"protected": env.Protected, "enc": env.Enc, "ct": env.Ct, "sig": env.Sig}
	res, err := c.callTool(ctx, peer, "sealed_call", wire)
	if err != nil {
		return nil, nil, err
	}
	if form == "chain" && c.OnChainSent != nil {
		// The peer has now seen our current leaf, whatever it answered: an
		// envelope that carried the chain is never answered chain_required.
		c.OnChainSent(peer)
	}
	if res.IsError {
		// §13.2: only a refusal that precedes the open may arrive in plaintext.
		if code, _ := refusalCode(res); !plaintextLegal[code] {
			return nil, nil, &errUnattributable{code: code}
		}
		return nil, res, nil
	}
	if len(res.Content) == 0 {
		return nil, nil, fmt.Errorf("outbound: empty sealed result")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, nil, fmt.Errorf("outbound: sealed result is not text")
	}
	var out hdtpidentity.Envelope
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		return nil, nil, fmt.Errorf("outbound: sealed result: %w", err)
	}
	opened, err := hdtpidentity.OpenResult(out, hdtpidentity.OpenOpts{
		Recipient: sender, RecipientPublic: senderPublic, MsgID: msgID, Now: now, Pins: []hdtpidentity.Pin{pinOf(peer)},
		ExpectedRoot: peer.Root, ExpectedEndpoint: peer.Endpoint,
	})
	if err != nil {
		return nil, nil, &errUnverifiable{why: err.Error()}
	}
	if len(opened.LeafUpdate) > 0 {
		// A renewal learned from the answer: the newer leaf replaces the pin
		// as it passes (§14.3).
		if _, _, err := c.repin(peer, opened.LeafUpdate); err != nil {
			return nil, nil, err
		}
	}
	if opened.Error != nil {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(opened.Error, &e)
		text := string(opened.Error)
		if e.Code != "" {
			text = `{"code":"` + e.Code + `"}`
		}
		return nil, &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil
	}
	return opened.Result, nil, nil
}

// chainFromGetCard asks the peer for its card in plaintext — over the chain as
// our client certificate — and returns the leaf of a chain that validates to
// the pinned root at the dialed address and is not older than the pin.
func (c *Client) chainFromGetCard(ctx context.Context, peer Peer) ([]byte, error) {
	// Plaintext, and so refused to a peer that requires sealing, as every plaintext call is.
	if peer.Seal == "required" {
		return nil, fmt.Errorf("%w: peer requires sealed calls", ErrSealRequired)
	}
	res, err := c.callTool(ctx, peer, "get_card", map[string]any{})
	if err != nil {
		return nil, err
	}
	if res.IsError || len(res.Content) == 0 {
		return nil, errors.New("get_card refused")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, errors.New("get_card answered no text")
	}
	var out struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil || len(out.Chain) != 2 {
		return nil, errors.New("get_card carried no chain")
	}
	leafDER, errLeaf := hdtpidentity.DecodeB64url(out.Chain[0])
	rootDER, errRoot := hdtpidentity.DecodeB64url(out.Chain[1])
	if errLeaf != nil || errRoot != nil {
		return nil, errors.New("get_card's chain is not base64url")
	}
	chain := [][]byte{leafDER, rootDER}
	ok2, why, leaf := hdtpidentity.FollowRenewed(chain, peer.Root, peer.Leaf, peer.Endpoint, c.now())
	if !ok2 {
		return nil, fmt.Errorf("get_card's chain: %s", why)
	}
	return leaf, nil
}

// mustSPKIOfLeaf is the pinned leaf's key, or nil for a leaf that does not parse.
func mustSPKIOfLeaf(leaf []byte) []byte {
	parsed, err := hdtpidentity.Parse(leaf)
	if err != nil {
		return nil
	}
	return parsed.SPKI
}
