// Package outbound implements calls TO contacts (SPEC §10.3): the account keypair
// as client certificate — sent unconditionally via GetClientCertificate, because an
// edge's CertificateRequest may advertise CAs a self-signed identity cannot satisfy
// and Go's default selection would then silently send nothing — server validation
// per HDTP §2 (pinned fingerprint first, else WebPKI for the hostname), and the
// outbound half of the seal policy (SPEC §4.6).
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// ErrSealRequired is the local refusal to send a plaintext call to a peer whose card says
// `seal: required` (SPEC.md §4, HDTP §13.4). It is returned wrapped (errors.Is) by CallTool,
// before any bytes leave the node.
var ErrSealRequired = errors.New("seal_required")

// RateLimited is a call this host refused to send because the calling identity's outbound budget
// is spent (HDTP §12's buckets, applied to what an identity sends as well as what it receives).
// Nothing left the host. RetryAfter is how long until the budget holds a call again.
type RateLimited struct{ RetryAfter time.Duration }

// Error reports the wait in whole seconds, rounded up, in the `rate_limited:` form.
func (e *RateLimited) Error() string {
	secs := int(math.Ceil(e.RetryAfter.Seconds()))
	return fmt.Sprintf("rate_limited: this identity has sent as many calls as its budget allows for now; try again in %d s (retry_after %d)", secs, secs)
}

// Peer is the contact-card view the client needs (SPEC §9.3).
type Peer struct {
	Endpoint string // the address the pinned leaf names (HDTP §2) — a card carries no separate one
	Seal     string // X-HDTP-SEAL: none | optional | required ("" = none)
	// A contact is pinned by its root (HDTP §2, §14.3). Root is that root's fingerprint — the
	// identity — Leaf is the latest leaf accepted, whose key is what the call is sealed to and
	// the answer verified under, and ChainSeen says this contact has already seen OUR current
	// leaf, so the call carries our leaf's fingerprint rather than the chain (§13.2).
	//
	// There was a `Fingerprint` beside `Root`, holding the same value. It was once the pinned
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
// neither. It used to be asked of a `Protocol` field that every construction set alike.
func (p Peer) Known() bool { return p.Root != "" && len(p.Leaf) > 0 }

// takesPlaintext reports whether this peer's card lets an unsealed call reach it (HDTP §13.4):
// every policy but `required`. CallTool refuses a plaintext call to a peer it is false for, and
// the sealed exchange asks its get_card of one sealed rather than in plaintext.
func (p Peer) takesPlaintext() bool { return p.Seal != "required" }

// Client makes calls from one account's identity to contacts. Build one per account and set the
// hooks the host needs; the zero value of each hook means "do nothing".
type Client struct {
	// Keypair is the account's identity key; its chain, when it has one, is what sealed calls carry.
	// A keypair with no chain cannot seal.
	Keypair *identity.Keypair
	// Cert is the certificate presented as the TLS client certificate, to every server, unconditionally.
	Cert tls.Certificate
	// Roots are the roots the WebPKI branch of server validation uses.
	Roots *x509.CertPool // nil = system roots; injectable for tests
	// Now is the clock the exchange dates envelopes and validates chains
	// by; nil means time.Now.
	Now func() time.Time
	// OnChainSent is told that a peer has been sent our chain, so the host
	// records that the next call may carry the fingerprint (HDTP §13.2).
	OnChainSent func(peer Peer)
	// OnRepin is told of a newer leaf accepted for a peer — from a result, a
	// certificate_renewed answer, or get_card — so the host moves the pin
	// (HDTP §14.3, §14.4). spki is the new leaf's key.
	OnRepin func(peer Peer, leaf, spki []byte)
	// DialContext overrides how the endpoint's host is reached; nil dials it.
	// A test maps a leaf's endpoint host onto a local listener with it.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Budget, when set, spends one of the calling identity's outbound calls to peer — tool is
	// the tool called, or "tools/list" — before anything leaves the host, and refuses: a
	// *RateLimited with how long until it holds one again, or any other error when no budget
	// could be asked (the node's limits sidecar is not answering, and nothing is sent). Every call
	// out passes it once: CallTool, ListTools, and the sealed exchange (Call and SealedCall reach
	// one of them, never two).
	Budget func(peer Peer, tool string) error
}

// spend is Budget: nil when the call may leave.
func (c *Client) spend(peer Peer, tool string) error {
	if c.Budget == nil {
		return nil
	}
	return c.Budget(peer, tool)
}

// tlsConfig builds the per-peer TLS client configuration implementing HDTP §2's
// server-side rule: accept iff the presented SPKI matches the pinned contact
// fingerprint, else require WebPKI validity for the endpoint hostname.
func (c *Client) tlsConfig(peer Peer, hostname string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is fully custom below; the default chain check must not run
		// first or pinned self-signed servers could never connect.
		InsecureSkipVerify: true, // #nosec G402 -- VerifyPeerCertificate below pins by SPKI (HDTP §2)
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
			// (a2) HDTP 1.0: the contact's own chain as the server certificate
			// (HDTP §2), validated to the pinned root at the dialed address.
			if peer.Known() && len(rawCerts) == 2 {
				vr := hdtpidentity.ValidateChain([][]byte{rawCerts[0], rawCerts[1]}, hdtpidentity.ChainOpts{Now: c.now(), ExpectedRoot: peer.Root, ExpectedEndpoint: peer.Endpoint})
				if vr.OK {
					return nil
				}
			}
			// There is no third way. A pinned peer is recognised by the chain
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

// HTTPClient returns a client that dials the peer under the rules above: TLS 1.2 or later, the
// account's certificate offered whatever the server asks for, and the server accepted only if it
// presents the peer's chain (leaf then root) validating to the pinned root at Peer.Endpoint, or a
// WebPKI-valid certificate for the endpoint's hostname. Requests time out after 30 seconds. It
// returns an error only when Endpoint does not parse as a URL.
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

// CallOptions are the per-call choices of CallTool.
type CallOptions struct {
	// Plaintext forces an unsealed call; refused locally against a
	// seal-required peer (SPEC §4.6) before any bytes leave the node.
	Plaintext bool
}

// CallTool invokes one tool on the peer as an unsealed MCP call; the seal decision is Call's, not
// this method's. It returns an error wrapping ErrSealRequired when the peer requires sealing and
// opts.Plaintext is set, spends the outbound budget (when set) before dialling, and does nothing
// else with opts. Sealing of the call itself rides the sealed_call wrapper (SealedCall); the outbound
// seal DECISION is Call's, so policy has exactly one home.
//
// The go-sdk client speaks MCP 2026-07-28 first: against a stateless peer — a node, BatonDeck —
// the exchange is two POSTs, `server/discover` and the call, with no session, no standalone GET
// and no DELETE (node TestASealedCallCompletesFromEitherMCPEra). The discover is the SDK's:
// Client.Connect sends it (or `initialize`) before anything else, and go-sdk v1.8.0 has no way to
// call a tool without Connect. A peer that answers only the handshake revisions is served the
// handshake the SDK falls back to.
func (c *Client) CallTool(ctx context.Context, peer Peer, tool string, args map[string]any, opts CallOptions) (*mcp.CallToolResult, error) {
	if opts.Plaintext && !peer.takesPlaintext() {
		return nil, fmt.Errorf("%w: peer requires sealed calls", ErrSealRequired)
	}
	if err := c.spend(peer, tool); err != nil {
		return nil, err
	}
	return c.callTool(ctx, peer, tool, args)
}

// callTool is CallTool without the budget: the wire half of an exchange that has already spent it
// (the sealed exchange's `sealed_call`, and the `get_card` it asks when an answer cannot be verified
// — in plaintext of a peer that takes plaintext, inside a `sealed_call` of one that requires sealing).
func (c *Client) callTool(ctx context.Context, peer Peer, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	hc, err := c.HTTPClient(peer)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "hdtp-gateway", Version: "1"}, nil)
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
// one method every node answers at every tier, sealed or not (HDTP §13.4), and
// the list comes back already filtered by the peer's switchboard for us.
func (c *Client) ListTools(ctx context.Context, peer Peer) ([]*mcp.Tool, error) {
	if err := c.spend(peer, "tools/list"); err != nil {
		return nil, err
	}
	hc, err := c.HTTPClient(peer)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "hdtp-gateway", Version: "1"}, nil)
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
// that says `none` gets plaintext (HDTP §13.4).
//
// The key sealed to is the one in the leaf held for the peer (`Peer.Leaf`). It used to be a
// separate argument that "may be nil: a contact re-pinned but not yet reconnected holds only a
// fingerprint" — a state key rotation produced — and a nil one sent the call PLAINTEXT to an
// `optional` peer and failed it outright for a `required` one. HDTP had a way into that state too:
// a contact we requested was stored with its leaf and without the leaf's key, so once they
// accepted, every call to them downgraded. The key is in the leaf; nothing needs to carry it twice.
func (c *Client) Call(ctx context.Context, peer Peer, tool string, args map[string]any, msgID string) (*mcp.CallToolResult, error) {
	if peer.Seal == "required" || peer.Seal == "optional" {
		return c.SealedCall(ctx, peer, tool, args, msgID)
	}
	return c.CallTool(ctx, peer, tool, args, CallOptions{Plaintext: true})
}

// SealedCall wraps one inner tools/call in an envelope sealed to the peer's leaf key, invokes the
// peer's `sealed_call`, and opens the sealed answer (HDTP §13.2).
//
// It returns an error, with nothing sent, for a peer we hold no root and leaf for or an account
// whose keypair has no chain, and the budget's error when the budget refuses. A refusal the peer
// sent in plaintext that is legal before the envelope opens (see plaintextLegal in seal.go)
// comes back as an IsError result carrying its code; any other plaintext refusal is an error,
// because past the open the peer would have sealed it. msgID is the envelope's msg_id, which the
// answer has to echo.
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
// its root and a call is sealed to its leaf's key (seal.go); a peer we hold neither for is
// refused here, because there is nothing to seal to and nothing to verify the answer under.
func (c *Client) exchange(ctx context.Context, peer Peer, method string, params map[string]any, msgID string) ([]byte, *mcp.CallToolResult, error) {
	if !c.canSeal(peer) {
		return nil, nil, fmt.Errorf("outbound: no root and leaf are held for %s, so there is nothing to seal to or verify under; add them from their card", peer.name())
	}
	tool := method
	if name, ok := params["name"].(string); ok && method == "tools/call" {
		tool = name
	}
	if err := c.spend(peer, tool); err != nil {
		return nil, nil, err
	}
	return c.sealedExchange(ctx, peer, method, params, msgID)
}
