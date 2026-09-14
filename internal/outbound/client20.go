package outbound

// PACT 2.0 sending (PACT §13.2, §14.3, §14.4): toward a contact pinned by its
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

	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// chain is [leaf, root] for a 2.0 identity, nil for a 1.x one.
func (c *Client) chain() [][]byte {
	if c.Keypair == nil || c.Keypair.Protocol != 2 || len(c.Keypair.Leaf) == 0 || len(c.Keypair.Root) == 0 {
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

// speaks20 reports whether this exchange is a 2.0 one: our identity holds a
// chain and the peer is pinned by its root.
func (c *Client) speaks20(peer Peer) bool { return peer.Protocol == 2 && c.chain() != nil }

// pinOf is the pin the answer is opened against.
func pinOf(peer Peer) pactidentity.Pin {
	return pactidentity.Pin{Root: peer.Root, Endpoint: peer.Endpoint, Leaf: pactidentity.B64url(peer.Leaf), State: "active"}
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
	parsed, err := pactidentity.Parse(leaf)
	if err != nil {
		return peer, nil, fmt.Errorf("outbound: the new leaf does not parse: %w", err)
	}
	peer.Leaf = leaf
	if c.OnRepin != nil {
		c.OnRepin(peer, leaf, parsed.SPKI)
	}
	return peer, parsed.SPKI, nil
}

// sealedExchange20 is one 2.0 request and its answer, with the three
// one-time follow-ups of PACT §13.2 and §14.4 applied.
func (c *Client) sealedExchange20(ctx context.Context, peer Peer, peerSPKI []byte, method string, params map[string]any, msgID string) ([]byte, *mcp.CallToolResult, error) {
	if pactidentity.Fingerprint(peerSPKI) != pactidentity.Fingerprint(mustSPKIOfLeaf(peer.Leaf)) {
		return nil, nil, fmt.Errorf("outbound: the pinned key is not the pinned leaf's")
	}
	form := "chain"
	if peer.ChainSeen {
		form = "leaf"
	}
	plain, refusal, err := c.attempt20(ctx, peer, peerSPKI, method, params, msgID, form)
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
				return c.attempt20(ctx, peer, peerSPKI, method, params, msgID, "chain")
			}
		case "certificate_renewed":
			// The key we sealed to has been renewed. The chain proves nothing by
			// itself: follow it only to the pinned root at the dialed address,
			// and only forward (§14.4). Once.
			var chain [][]byte
			if cs, ok := data["chain"].([]any); ok {
				for _, s := range cs {
					if str, ok := s.(string); ok {
						chain = append(chain, pactidentity.FromB64url(str))
					}
				}
			}
			ok, why, leaf := pactidentity.FollowRenewed(chain, peer.Root, peer.Leaf, peer.Endpoint, c.now())
			if !ok {
				return nil, refusal, fmt.Errorf("outbound: certificate_renewed not followed: %s", why)
			}
			next, spki, err := c.repin(peer, leaf)
			if err != nil {
				return nil, refusal, err
			}
			return c.attempt20(ctx, next, spki, method, params, msgID, form)
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
		next, spki, rerr := c.repin(peer, leaf)
		if rerr != nil {
			return nil, nil, rerr
		}
		return c.attempt20(ctx, next, spki, method, params, msgID, form)
	default:
		return nil, nil, err
	}
}

// errUnverifiable is an answer that opened but could not be verified against
// any leaf this caller holds for the peer.
type errUnverifiable struct{ why string }

func (e *errUnverifiable) Error() string { return "outbound: unverifiable answer: " + e.why }

// attempt20 seals one request in the given form, sends it, and opens the answer.
func (c *Client) attempt20(ctx context.Context, peer Peer, peerSPKI []byte, method string, params map[string]any, msgID, form string) ([]byte, *mcp.CallToolResult, error) {
	recipient, err := pactidentity.ParseSPKI(peerSPKI)
	if err != nil {
		return nil, nil, fmt.Errorf("outbound: peer key: %w", err)
	}
	sender, err := identity.ToLib(c.Keypair)
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
	env, err := pactidentity.SealRequest(pactidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: form, SenderChain: c.chain(),
		Method: method, Params: pb, MsgID: msgID, TS: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("outbound: seal: %w", err)
	}
	wire := map[string]any{"protected": env.Protected, "enc": env.Enc, "ct": env.Ct, "sig": env.Sig}
	res, err := c.CallTool(ctx, peer, "sealed_call", wire, CallOptions{})
	if err != nil {
		return nil, nil, err
	}
	if form == "chain" && c.OnChainSent != nil {
		// The peer has now seen our current leaf, whatever it answered: an
		// envelope that carried the chain is never answered chain_required.
		c.OnChainSent(peer)
	}
	if res.IsError {
		return nil, res, nil
	}
	if len(res.Content) == 0 {
		return nil, nil, fmt.Errorf("outbound: empty sealed result")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, nil, fmt.Errorf("outbound: sealed result is not text")
	}
	var out pactidentity.Envelope
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		return nil, nil, fmt.Errorf("outbound: sealed result: %w", err)
	}
	opened, err := pactidentity.OpenResult(out, pactidentity.OpenOpts{
		Recipient: sender, MsgID: msgID, Now: now, Pins: []pactidentity.Pin{pinOf(peer)},
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
	res, err := c.CallTool(ctx, peer, "get_card", map[string]any{}, CallOptions{Plaintext: true})
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
	chain := [][]byte{pactidentity.FromB64url(out.Chain[0]), pactidentity.FromB64url(out.Chain[1])}
	ok2, why, leaf := pactidentity.FollowRenewed(chain, peer.Root, peer.Leaf, peer.Endpoint, c.now())
	if !ok2 {
		return nil, fmt.Errorf("get_card's chain: %s", why)
	}
	return leaf, nil
}

// mustSPKIOfLeaf is the pinned leaf's key, or nil for a leaf that does not parse.
func mustSPKIOfLeaf(leaf []byte) []byte {
	parsed, err := pactidentity.Parse(leaf)
	if err != nil {
		return nil
	}
	return parsed.SPKI
}
