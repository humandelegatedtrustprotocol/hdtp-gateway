package cli

// Relay mode in both directions (SPEC §10.5, PACT §9), wired into `serve`:
//
//   - as a RELAY for other people, when `relay: true` — the surface mounts at
//     /relay/mcp on the public listener, verifying senders by their client
//     certificate and never holding a key that opens what it stores;
//   - as a relay CLIENT, when `gateway_url` is set — every account syncs its
//     allow-list to that gateway, polls it, and re-runs each fetched envelope
//     through the standard open order before anything is stored.
//
// The card advertises `gateway_url` as `X-PACT-GATEWAY` (node.Card), which is
// what lets a peer fall back to it after a failed direct delivery.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/public"
	"github.com/tech-sumit/pact-gateway/internal/relay"
)

// relayHandlers builds the two relay surfaces: PACT §9's three MCP verbs at
// /relay/mcp, and the relay's own allow-list control plane at
// /relay/allowlist. Caller identity for both comes from the TLS client
// certificate the listener recorded — the relay has no other way to know who is
// calling, which is exactly why it cannot run behind a terminating edge.
// relayHandlers takes a FUNCTION for the recipient list, not a snapshot: the
// list is a portal knob (P14-13), and a relay that captured it at startup would
// keep serving nodes the owner had just removed until the next restart — the same
// stale-state failure P12-02, P12-05 and P14-05e each turned out to be.
func relayHandlers(st store.Store, serves func() []string, auditFn func(action, resource, outcome string)) (mcpSurface, control http.Handler) {
	srv := &relay.Server{
		Store: st,
		Caller: func(ctx context.Context) ([]byte, string, bool) {
			f := public.FactsFrom(ctx)
			if len(f.ClientCertSPKI) == 0 || f.ClientCertFingerprint == "" {
				return nil, "", false
			}
			return f.ClientCertSPKI, f.ClientCertFingerprint, true
		},
		Audit:  auditFn,
		Serves: dynamicServes(serves),
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv.MCPServer()
	}, &mcp.StreamableHTTPOptions{
		// Same reason as the per-account handler: a relay behind a tunnel is
		// reached over loopback with a public Host. A relay is necessarily TLS —
		// it verifies senders by their client certificate (§10.5).
		DisableLocalhostProtection: true,
	}), srv.AllowlistHandler()
}

// dynamicServes re-reads the configured list on every check, so a change made in
// the portal applies to the very next registration and relay_call.
func dynamicServes(list func() []string) func(string) bool {
	return func(fpr string) bool {
		gate := servesOnly(list())
		if gate == nil {
			return true // empty list means an OPEN relay, the documented default
		}
		return gate(fpr)
	}
}

// servesOnly turns the configured recipient list into the relay's registration
// gate. An EMPTY list means nil — an open relay, which is the documented default
// — so the knob is what changes behaviour, never an upgrade.
func servesOnly(fprs []string) func(string) bool {
	if len(fprs) == 0 {
		return nil
	}
	set := make(map[string]bool, len(fprs))
	for _, f := range fprs {
		set[f] = true
	}
	return func(fpr string) bool { return set[fpr] }
}

// gatewayTransport speaks to a remote relay as one account, over mTLS with that
// account's identity certificate.
type gatewayTransport struct {
	client *outbound.Client
	peer   outbound.Peer
	// controlURL is the relay's allow-list endpoint. It is a plain HTTPS POST,
	// not an MCP call: PACT §9 has three relay verbs and this is not one.
	controlURL string
}

func (g gatewayTransport) Call(ctx context.Context, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	// Relay traffic is plaintext MCP over mTLS: the payload it carries is
	// already sealed, and the relay must be able to read the envelope's routing
	// header without opening anything.
	return g.client.CallTool(ctx, g.peer, tool, args, outbound.CallOptions{Plaintext: true})
}

// postAllowlist tells the relay who may queue for this account, over the same
// pinned mTLS connection the MCP surface uses. The relay reads the recipient
// from the client certificate, so this body names only the senders.
func (g gatewayTransport) postAllowlist(ctx context.Context, senders []string) error {
	hc, err := g.client.HTTPClient(g.peer)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"senders": senders})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("relay: allow-list sync refused (%s)", res.Status)
	}
	return nil
}

// startRelayClients runs one fetch loop per account against the configured
// gateway. Each loop stops when ctx ends.
func startRelayClients(ctx context.Context, cfg *core.Config, nd *node.Node, st store.Store,
	idm *identity.Manager, auditFn func(action, resource, outcome string), stderr io.Writer) error {

	if cfg.GatewayURL == "" {
		return nil
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return err
	}
	for _, acct := range accounts {
		sealed, err := st.GetAccountSealedKey(ctx, acct.ID)
		if err != nil {
			return fmt.Errorf("relay client: account %s: %w", acct.Slug, err)
		}
		kp, err := idm.LoadKeypair(sealed)
		if err != nil {
			return fmt.Errorf("relay client: account %s: %w", acct.Slug, err)
		}
		der, err := identity.SelfSignedCert(kp, acct.Slug)
		if err != nil {
			return err
		}
		// nil Roots = the system roots, which this path depends on: the gateway is
		// pinned by nothing (see below), so WebPKI for its hostname is the ONLY
		// thing that authenticates it. An empty pool made that impossible.
		client := &outbound.Client{
			Keypair: kp,
			Cert:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer},
		}
		// The gateway is pinned by nothing here: it is a service the owner
		// chose, and everything it carries is sealed to this account's key.
		// What it can do is refuse or drop, never read (SPEC §10.5).
		transport := gatewayTransport{
			client: client,
			peer: outbound.Peer{
				Endpoint: cfg.GatewayURL + "/relay/mcp", Fingerprint: cfg.GatewayFingerprint,
			},
			controlURL: cfg.GatewayURL + "/relay/allowlist",
		}

		accountID := acct.ID
		rc := &relay.Client{
			Transport:     transport,
			PostAllowlist: transport.postAllowlist,
			Audit:         func(action, resource, outcome string) { auditFn(action, resource, outcome) },
			Process: func(ctx context.Context, item relay.QueuedItem) error {
				return nd.DeliverSealed(ctx, accountID, item.Envelope, public.DeliveryRelay)
			},
		}
		// The allow-list is this account's active contacts and nobody else
		// (SPEC §10.5). It is re-sent whenever it changes, so a contact added
		// after startup can still be queued for.
		rc.Allowlist = func(ctx context.Context) ([]string, error) {
			return activeContactFingerprints(ctx, st, accountID)
		}
		senders, err := activeContactFingerprints(ctx, st, acct.ID)
		if err != nil {
			return err
		}
		if err := rc.SyncAllowlist(ctx, senders); err != nil {
			// A gateway that is down must not stop the node from serving; the
			// loop retries with backoff.
			fmt.Fprintf(stderr, "relay: allow-list sync to %s failed: %v\n", cfg.GatewayURL, err)
		}
		go rc.Run(ctx, nil)
		auditFn("relay_client", "account:"+acct.ID+" gateway:"+cfg.GatewayURL, "started")
	}
	return nil
}

func activeContactFingerprints(ctx context.Context, st store.Store, accountID string) ([]string, error) {
	list, err := st.ListContacts(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, c := range list {
		if c.Status == "active" {
			out = append(out, c.Fingerprint)
		}
	}
	return out, nil
}
