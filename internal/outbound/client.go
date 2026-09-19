// Package outbound implements calls TO contacts (SPEC §10.3): the account keypair
// as client certificate — sent unconditionally via GetClientCertificate, because an
// edge's CertificateRequest may advertise CAs a self-signed identity cannot satisfy
// and Go's default selection would then silently send nothing — server validation
// per PACT §2 (pinned fingerprint first, else WebPKI for the hostname), and the
// outbound half of the seal policy (SPEC §4.6).
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

var ErrSealRequired = errors.New("seal_required")

// Peer is the contact-card view the client needs (SPEC §9.3).
type Peer struct {
	Endpoint string // the address the pinned leaf names (PACT §2) — a card carries no separate one
	Seal     string // X-PACT-SEAL: none | optional | required ("" = none)
	// A contact is pinned by its root (PACT §2, §14.3). Root is that root's fingerprint — the
	// identity — Leaf is the latest leaf accepted, whose key is what the call is sealed to and
	// the answer verified under, and ChainSeen says this contact has already seen OUR current
	// leaf, so the call carries our leaf's fingerprint rather than the chain (§13.2).
	//
	// There was a `Fingerprint` beside `Root`, holding the same value. In 1.x it was the pinned
	// KEY's, and it was what TLS and the envelope were checked against; by the time it went,
	// two error messages were all that read it.
	Root      string
	Leaf      []byte
	ChainSeen bool
}

// name is how an error says which peer it is about: the root when one is pinned, and the address
// when the peer is somebody we hold no root for — which is what the error is then about.
func (p Peer) name() string {
	if p.Root != "" {
		return p.Root
	}
	return p.Endpoint
}

// Known reports whether we hold what it takes to recognise this peer: the root it is pinned by
// and a leaf under it. Every peer built from a pin or a card has both; the zero Peer has
// neither. It used to be asked as `Protocol == 2`, a field every construction set to 2.
func (p Peer) Known() bool { return p.Root != "" && len(p.Leaf) > 0 }

type Client struct {
	Keypair *identity.Keypair
	Cert    tls.Certificate
	Roots   *x509.CertPool // nil = system roots; injectable for tests
	// Now is the clock the 2.0 exchange dates envelopes and validates chains
	// by; nil means time.Now.
	Now func() time.Time
	// OnChainSent is told that a peer has been sent our chain, so the host
	// records that the next call may carry the fingerprint (PACT §13.2).
	OnChainSent func(peer Peer)
	// OnRepin is told of a newer leaf accepted for a peer — from a result, a
	// certificate_renewed answer, or get_card — so the host moves the pin
	// (PACT §14.3, §14.4). spki is the new leaf's key.
	OnRepin func(peer Peer, leaf, spki []byte)
	// DialContext overrides how the endpoint's host is reached; nil dials it.
	// A test maps a leaf's endpoint host onto a local listener with it.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// tlsConfig builds the per-peer TLS client configuration implementing PACT §2's
// server-side rule: accept iff the presented SPKI matches the pinned contact
// fingerprint, else require WebPKI validity for the endpoint hostname.
func (c *Client) tlsConfig(peer Peer, hostname string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is fully custom below; the default chain check must not run
		// first or pinned self-signed servers could never connect.
		InsecureSkipVerify: true, // #nosec G402 -- VerifyPeerCertificate below pins by SPKI (PACT §2)
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &c.Cert, nil // unconditional (SPEC §10.3)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("outbound: server presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("outbound: %w", err)
			}
			// (a2) PACT 2.0: the contact's own chain as the server certificate
			// (PACT §2), validated to the pinned root at the dialed address.
			if peer.Known() && len(rawCerts) == 2 {
				vr := pactidentity.ValidateChain([][]byte{rawCerts[0], rawCerts[1]}, pactidentity.ChainOpts{Now: c.now(), ExpectedRoot: peer.Root, ExpectedEndpoint: peer.Endpoint})
				if vr.OK {
					return nil
				}
			}
			// There is no third way. A pinned 2.0 peer is recognised by the chain
			// above — validated to the root we pinned, at the address we dialed —
			// and everything else by WebPKI for the hostname, which is what a
			// terminating edge presents.
			//
			// WebPKI for the hostname:
			inter := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if ic, err := x509.ParseCertificate(raw); err == nil {
					inter.AddCert(ic)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{
				DNSName: hostname, Roots: c.Roots, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("outbound: server presented neither a chain under the pinned root nor a WebPKI-valid certificate for %s: %w", hostname, err)
			}
			return nil
		},
	}
}

// HTTPClient returns a client that dials the peer under the rules above.
func (c *Client) HTTPClient(peer Peer) (*http.Client, error) {
	u, err := url.Parse(peer.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig(peer, u.Hostname()),
			DialContext:     c.DialContext,
		},
	}, nil
}

type CallOptions struct {
	// Plaintext forces an unsealed call; refused locally against a
	// seal-required peer (SPEC §4.6) before any bytes leave the node.
	Plaintext bool
}

// CallTool connects an MCP client session to the peer and invokes one tool.
// Sealing of the call itself rides the sealed_call wrapper wired in P1-08/P1-11;
// the outbound seal DECISION lives here so policy has exactly one home.
func (c *Client) CallTool(ctx context.Context, peer Peer, tool string, args map[string]any, opts CallOptions) (*mcp.CallToolResult, error) {
	if peer.Seal == "required" && opts.Plaintext {
		return nil, fmt.Errorf("%w: peer requires sealed calls", ErrSealRequired)
	}
	hc, err := c.HTTPClient(peer)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "pact-gateway", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: peer.Endpoint, HTTPClient: hc,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	defer session.Close()
	return session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
}

// ListTools asks the peer what this identity may call there. tools/list is the
// one method every node answers at every tier, sealed or not (PACT §13.4), and
// the list comes back already filtered by the peer's switchboard for us.
func (c *Client) ListTools(ctx context.Context, peer Peer) ([]*mcp.Tool, error) {
	hc, err := c.HTTPClient(peer)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "pact-gateway", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: peer.Endpoint, HTTPClient: hc}, nil)
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	defer session.Close()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// Call makes a tool call the way the PEER'S CARD says it must be made.
//
// The seal decision is one rule and belongs in one place — every outbound call site used to
// choose for itself. A peer whose card says `required` or `optional` is sealed to; only a peer
// that says `none` gets plaintext (PACT §13.4).
//
// The key sealed to is the one in the leaf held for the peer (`Peer.Leaf`). It used to be a
// separate argument that "may be nil: a contact re-pinned but not yet reconnected holds only a
// fingerprint" — a state 1.x key rotation produced — and a nil one sent the call PLAINTEXT to an
// `optional` peer and failed it outright for a `required` one. 2.0 had a way into that state too:
// a contact we requested was stored with its leaf and without the leaf's key, so once they
// accepted, every call to them downgraded. The key is in the leaf; nothing needs to carry it twice.
func (c *Client) Call(ctx context.Context, peer Peer, tool string, args map[string]any, msgID string) (*mcp.CallToolResult, error) {
	if peer.Seal == "required" || peer.Seal == "optional" {
		return c.SealedCall(ctx, peer, tool, args, msgID)
	}
	return c.CallTool(ctx, peer, tool, args, CallOptions{Plaintext: true})
}

// SealedCall wraps one inner tools/call in an envelope sealed to the peer's leaf key, invokes the
// peer's `sealed_call`, and opens the sealed answer (PACT §13.2).
func (c *Client) SealedCall(ctx context.Context, peer Peer, tool string, args map[string]any, msgID string) (*mcp.CallToolResult, error) {
	plain, refusal, err := c.exchange(ctx, peer, "tools/call",
		map[string]any{"name": tool, "arguments": args}, msgID)
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return refusal, nil // wrapper-level refusal: the code travels in plain text
	}
	var inner mcp.CallToolResult
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, fmt.Errorf("outbound: inner result: %w", err)
	}
	return &inner, nil
}

// SealedListTools is tools/list inside a sealed envelope (SPEC §4.5): the only
// way a caller behind a terminating edge learns its real surface, since the
// plaintext list there arrives with no identity and is answered as to a
// stranger. The peer applies its own switchboard to the answer.
func (c *Client) SealedListTools(ctx context.Context, peer Peer, msgID string) ([]*mcp.Tool, error) {
	plain, refusal, err := c.exchange(ctx, peer, "tools/list", nil, msgID)
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		msg := "refused"
		if len(refusal.Content) > 0 {
			if tc, ok := refusal.Content[0].(*mcp.TextContent); ok {
				msg = tc.Text
			}
		}
		return nil, fmt.Errorf("outbound: sealed tools/list: %s", msg)
	}
	var out struct {
		Tools []*mcp.Tool `json:"tools"`
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, fmt.Errorf("outbound: inner tools/list: %w", err)
	}
	return out.Tools, nil
}

// exchange seals one inner request to the peer and opens the answer. A contact is pinned by
// its root and a call is sealed to its leaf's key (client20.go); a peer we hold neither for is
// refused here, because there is nothing to seal to and nothing to verify the answer under.
func (c *Client) exchange(ctx context.Context, peer Peer, method string, params map[string]any, msgID string) ([]byte, *mcp.CallToolResult, error) {
	if !c.speaks20(peer) {
		return nil, nil, fmt.Errorf("outbound: no root and leaf are held for %s, so there is nothing to seal to or verify under; add them from their card", peer.name())
	}
	return c.sealedExchange20(ctx, peer, method, params, msgID)
}
