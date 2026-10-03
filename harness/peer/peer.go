// Package peer acts as a contact's agent against a node's public surface.
//
// It reuses the product's own outbound client rather than reimplementing mTLS.
// That is possible even though the harness is a separate module: Go's internal
// rule is by IMPORT-PATH tree, and `…/hdtp-gateway/harness` sits inside
// `…/hdtp-gateway`, so `internal/outbound` is importable here. Reimplementing the
// dialling would have meant a scenario could pass against a peer that the real
// product could never have talked to.
package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Agent is one contact's agent: an identity plus the client that speaks for it.
//
// An identity is a person's self-signed ROOT and a leaf the root issued to the
// host, and it is the root a node pins (HDTP §2). The leaf names the address this
// agent answers at — it never actually serves, but a leaf must name one, and it
// MUST NOT be a loopback address (§14.2 rule 5), so it names a routable-looking one.
type Agent struct {
	Keypair *identity.Keypair
	Client  *outbound.Client
	// Root is this agent's identity: what a node pins it by.
	Root string
	// Leaf is the certificate its chain presents, DER.
	Leaf []byte
	// Endpoint is the address that leaf names.
	Endpoint string
	rootCert []byte
	name     string

	routeMu sync.Mutex
	routes  map[string]string // "host:port" as an endpoint names it -> where it is published
}

// dial is this agent's resolver: a name a target's leaf carries goes to wherever the harness
// published that node, and anything else is dialled as written.
func (a *Agent) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	a.routeMu.Lock()
	if to, ok := a.routes[addr]; ok {
		addr = to
	}
	a.routeMu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// route records where a target is really listening.
func (a *Agent) route(t Target) {
	if t.Dial == "" {
		return
	}
	u, err := url.Parse(t.Endpoint)
	if err != nil {
		return
	}
	hostport := u.Host
	if u.Port() == "" {
		hostport = net.JoinHostPort(u.Hostname(), "443")
	}
	a.routeMu.Lock()
	a.routes[hostport] = t.Dial
	a.routeMu.Unlock()
}

// NewAgent mints a fresh identity and the client that presents it. Each scenario
// gets its own, because identity IS the caller in HDTP — sharing one between two
// simulated contacts would make every tier and permission assertion meaningless.
func NewAgent(name string) (*Agent, error) {
	if name == "" {
		name = "harness-peer"
	}
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		return nil, fmt.Errorf("peer: generating identity: %w", err)
	}
	rootKey, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		return nil, fmt.Errorf("peer: generating root: %w", err)
	}
	rootCert, err := hdtpidentity.BuildRoot(hdtpidentity.RootOpts{
		CN: name, Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		return nil, fmt.Errorf("peer: minting root certificate: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("peer: host key: %w", err)
	}
	hostPub, err := hdtpidentity.ParseSPKI(spki)
	if err != nil {
		return nil, fmt.Errorf("peer: host key: %w", err)
	}
	endpoint := "https://" + name + ".harness.example/a/" + name + "/mcp"
	leaf, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: name, RootCN: name, RootKey: rootKey, HostPub: hostPub, URIs: []string{endpoint},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		return nil, fmt.Errorf("peer: minting leaf certificate: %w", err)
	}
	kp.Leaf, kp.Root = leaf, rootCert
	cert := tls.Certificate{Certificate: [][]byte{leaf, rootCert}, PrivateKey: kp.Signer}
	a := &Agent{
		Keypair: kp, Root: hdtpidentity.Fingerprint(rootKey.Public().SPKI),
		Leaf: leaf, Endpoint: endpoint, rootCert: rootCert, name: name,
		routes: map[string]string{},
	}
	// Roots is empty on purpose: a peer trusts the node by its PINNED ROOT, not
	// by WebPKI (HDTP §2). An empty pool means a mis-pinned peer fails closed.
	a.Client = &outbound.Client{Keypair: kp, Cert: cert, Roots: x509.NewCertPool(), DialContext: a.dial}
	return a, nil
}

// Card is this agent's contact card: the leaf, and the seal policy it claims.
func (a *Agent) Card(seal string) string {
	card, err := contacts.BuildCard(a.name, a.Leaf, seal)
	if err != nil {
		panic("peer: " + err.Error()) // a scenario's own name, which carries no control character
	}
	return card
}

// Fingerprint is this agent's HDTP §2 identity — its ROOT. It used to be the
// identity key's, because the key WAS the identity; a leaf key changes at
// every renewal and a root does not, so the root is what a node pins.
func (a *Agent) Fingerprint() string { return a.Root }

// LeafKid is the leaf key's fingerprint, which is what an envelope's `kid` names.
func (a *Agent) LeafKid() string { return a.Keypair.Fingerprint }

// Target names a node this agent calls.
type Target struct {
	// Endpoint is the node's MCP URL as its LEAF names it, e.g. https://alice.harness.example/a/alice/mcp.
	// A chain is validated against the address dialled (HDTP §14.2 rule 5), and a wallet does not
	// issue a leaf for a loopback address, so this is a name even when the node is a container
	// published on localhost.
	Endpoint string
	// Dial is where that name is really listening, e.g. 127.0.0.1:18443 — what DNS would say
	// for a real caller. Empty dials the endpoint as written.
	Dial string
	// Seal mirrors the peer's X-HDTP-SEAL, which decides whether Call seals.
	Seal string
	// Root and Leaf are the node's identity: the fingerprint of the root its chain must validate
	// to, and the leaf it presents — whose key is the one a call is sealed to. Without them
	// nothing can be validated and nothing sealed, and the client refuses rather than guessing.
	Root string
	Leaf []byte
}

// Peer is the outbound view of a target.
//
// This set a `Protocol` number when the root was known and passed the node's key beside the call; the
// node dropped both on 2026-09-19 (a pin is a root and a leaf, and the key is the leaf's). This
// module is compiled by no gate of the node's, so it went on not compiling for the rest of that
// day, until the pre-push hook — the only thing that builds it — refused the push.
func (t Target) Peer() outbound.Peer {
	return outbound.Peer{Endpoint: t.Endpoint, Seal: t.Seal, Root: t.Root, Leaf: t.Leaf}
}

// Call invokes one tool on the target and returns the decoded result content.
//
// msgID is the caller-supplied idempotency key of HDTP §6.2 — the SAME value must
// be reused across retries, which is what makes a retry safe.
func (a *Agent) Call(ctx context.Context, t Target, tool string, args map[string]any, msgID string) (string, error) {
	a.route(t)
	p := t.Peer()
	res, err := a.Client.Call(ctx, p, tool, args, msgID)
	if err != nil {
		return "", fmt.Errorf("peer: calling %s: %w", tool, err)
	}
	return renderResult(res)
}

// ListTools returns the tool names this node serves THIS agent.
//
// The list is the switchboard's answer, not a catalogue: SPEC §5.4 filters
// tools/list per caller, so an unknown identity sees exactly the guest tier. That
// makes this the cheapest end-to-end proof that real mTLS reached a real node and
// tier resolution ran — no pairing required.
func (a *Agent) ListTools(ctx context.Context, t Target) ([]string, error) {
	a.route(t)
	p := t.Peer()
	hc, err := a.Client.HTTPClient(p)
	if err != nil {
		return nil, fmt.Errorf("peer: building mTLS client: %w", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "harness-peer", Version: "1"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: t.Endpoint, HTTPClient: hc}, nil)
	if err != nil {
		return nil, fmt.Errorf("peer: connecting to %s: %w", t.Endpoint, err)
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("peer: listing tools: %w", err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
	}
	return names, nil
}

// renderResult flattens an MCP result to text, preserving the error flag: a peer
// that refuses is giving an ANSWER, and a driver that swallowed it would make a
// refusal look like a success.
func renderResult(res any) (string, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	var shape struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &shape); err != nil {
		return string(b), nil
	}
	text := ""
	for _, c := range shape.Content {
		text += c.Text
	}
	if shape.IsError {
		return text, fmt.Errorf("peer: the node refused: %s", text)
	}
	return text, nil
}
