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
	Endpoint    string // X-PACT-ENDPOINT
	Fingerprint string // X-PACT-KEY — the pinned identity
	Seal        string // X-PACT-SEAL: none | optional | required ("" = none)
	// PACT 2.0 (PACT §2, §14.3): a contact pinned by its root. Fingerprint is
	// then the root's, Root names it again, Leaf is the latest leaf accepted
	// (its key is what the call is sealed to and the answer verified under),
	// and ChainSeen says this contact has already seen OUR current leaf, so
	// the call carries our leaf's fingerprint rather than the chain (§13.2).
	Protocol  int
	Root      string
	Leaf      []byte
	ChainSeen bool
}

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
			if peer.Protocol == 2 && len(rawCerts) == 2 {
				vr := pactidentity.ValidateChain([][]byte{rawCerts[0], rawCerts[1]}, pactidentity.ChainOpts{Now: c.now(), ExpectedRoot: peer.Root, ExpectedEndpoint: peer.Endpoint})
				if vr.OK {
					return nil
				}
			}
			// (a) pinned identity as server certificate
			if fpr, err := identity.Fingerprint(leaf.PublicKey); err == nil && fpr == peer.Fingerprint {
				return nil
			}
			// (b) WebPKI for the hostname
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
				return fmt.Errorf("outbound: server is neither the pinned key nor WebPKI-valid for %s: %w", hostname, err)
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

// SealedCall wraps one inner tools/call in an envelope, invokes the peer's
// `sealed_call`, and opens the sealed answer (SPEC §4.5). peerSPKI is the
// recipient's public key — pinned at add-contact time, or taken from the invite
// landing page for a first, guest call — and MUST hash to peer.Fingerprint.
// spk carries OUR key inside the payload so an unpinned recipient can verify
// the signature (§4.4 step 6); it costs nothing to include when already pinned.
// Call makes a tool call the way the PEER'S CARD says it must be made.
//
// The seal decision is one rule and belongs in one place: every outbound call
// site was choosing for itself, and the rotation fan-out chose `Plaintext: true`
// unconditionally — so `account rotate` was refused `seal_required` by any peer
// whose card asks for sealing, silently losing that contact at grace expiry.
//
// peerSPKI may be nil: a contact re-pinned but not yet reconnected holds only a
// fingerprint (§3.9). Then a peer that REQUIRES sealing is a hard failure, and
// one that merely accepts it gets plaintext.
func (c *Client) Call(ctx context.Context, peer Peer, peerSPKI []byte, tool string, args map[string]any, msgID string) (*mcp.CallToolResult, error) {
	sealable := peer.Seal == "required" || peer.Seal == "optional"
	if sealable && len(peerSPKI) > 0 {
		return c.SealedCall(ctx, peer, peerSPKI, tool, args, msgID)
	}
	if peer.Seal == "required" {
		return nil, fmt.Errorf("outbound: %s requires sealed calls and only their "+
			"fingerprint is pinned — they must reach us once so their key can be recorded", peer.Fingerprint)
	}
	return c.CallTool(ctx, peer, tool, args, CallOptions{Plaintext: true})
}

func (c *Client) SealedCall(ctx context.Context, peer Peer, peerSPKI []byte, tool string, args map[string]any, msgID string) (*mcp.CallToolResult, error) {
	plain, refusal, err := c.exchange(ctx, peer, peerSPKI, "tools/call",
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
func (c *Client) SealedListTools(ctx context.Context, peer Peer, peerSPKI []byte, msgID string) ([]*mcp.Tool, error) {
	plain, refusal, err := c.exchange(ctx, peer, peerSPKI, "tools/list", nil, msgID)
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

// exchange seals one inner request to the peer and opens the answer. There is one
// generation: a contact is pinned by its root and speaks `v: 2` (client20.go). A
// contact that is not — a key pin from before 2.0 — is refused here rather than
// downgraded, because there is nothing to downgrade to.
func (c *Client) exchange(ctx context.Context, peer Peer, peerSPKI []byte, method string, params map[string]any, msgID string) ([]byte, *mcp.CallToolResult, error) {
	if !c.speaks20(peer) {
		return nil, nil, fmt.Errorf("outbound: %s is not a PACT 2.0 contact; add them again from their card to get their root", peer.Fingerprint)
	}
	return c.sealedExchange20(ctx, peer, peerSPKI, method, params, msgID)
}
