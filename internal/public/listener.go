// Package public implements the HDTP-facing surface (SPEC §5): the TLS listener,
// transport-fact extraction, and the route shell. Tiering, per-caller servers, and
// dispatch land in later tasks; this file owns everything at and below the connection.
package public

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// TransportFacts is what the transport layer proved about a request (SPEC §5.1).
// The certificate fingerprint here is a FACT, not an authorization: tiering and the
// unified identity rule (§3.5) are applied above.
type TransportFacts struct {
	ClientCertFingerprint string // "" when no certificate was presented
	// ClientCertSPKI is the presented key itself (SubjectPublicKeyInfo DER).
	// Pinning stores the full key, never just its hash (§9.2), so the plaintext
	// mTLS path must carry it exactly as the sealed path carries its leaf.
	ClientCertSPKI []byte
	// RemoteIP is the source address the node trusts for this request: the
	// adapter's own header behind a terminating edge, the socket otherwise, and
	// never a generic forwarded-for header (SPEC §5.7). Guest budgets key on it.
	RemoteIP string
	SrcAddr  string
	// HDTP 1.0 (HDTP §2, §14.2): a client that presented a chain — a leaf and
	// the root that issued it — that validated. ClientCertFingerprint is then
	// the ROOT's, ClientCertSPKI the leaf's key, ClientLeaf the leaf, and
	// ClientEndpoint the one address it names. That chain is the ONLY thing
	// that fills these fields: a single certificate, or a chain that does not
	// validate, establishes no identity at all, because in 2.0 the identity is
	// the root and a lone certificate names none.
	ClientLeaf     []byte
	ClientEndpoint string
	// ClientRoot is the root's own DER from that chain (migration 0029). The pin
	// keeps the root's fingerprint, and the chain does not come back: a contact
	// that connects here is the node's chance to keep the certificate itself.
	ClientRoot []byte
}

// ChainProven reports whether this connection's client presented a chain that validated — the
// only thing that establishes an identity at the transport (HDTP §2, §14.2). The fields above
// are filled together by that one event or not at all, so the leaf's presence is the fact; a
// `ClientProtocol` field used to sit beside them saying 2 exactly when it was there.
func (f TransportFacts) ChainProven() bool { return len(f.ClientLeaf) > 0 }

type factsKey struct{}

func FactsFrom(ctx context.Context) TransportFacts {
	f, _ := ctx.Value(factsKey{}).(TransportFacts)
	return f
}

// WithFacts attaches transport facts to a context: the listener's facts
// middleware calls it per request, and an in-process caller (a test) presents
// the facts the wire would have carried through the same function.
func WithFacts(ctx context.Context, f TransportFacts) context.Context {
	return context.WithValue(ctx, factsKey{}, f)
}

// Server is the public listener shell. The four route handlers are injected so the
// surface composes without import cycles; Accounts feeds slug routing and the
// single-account /mcp alias rule (SPEC §5.2).
type Server struct {
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Accounts       func() []string
	MCP            http.Handler // /a/{slug}/mcp (and /mcp alias when exactly one account)
	Invite         http.Handler // /i/{token}
	// Probe answers the reachability probe (SPEC §10.4) at tunnel.ProbePath;
	// nil disables it.
	Probe http.Handler
	// Inner wraps the routes INSIDE the facts middleware. Anything that needs
	// the caller's identity — rate limiting by fingerprint, for one — has to run
	// here: outside, the facts are not in the context yet and every caller looks
	// anonymous.
	Inner func(http.Handler) http.Handler
	// SourceIP resolves the address a request is budgeted against; nil uses the
	// socket. Behind a terminating edge the socket is the connector's, so the
	// node supplies the adapter's trusted-header rule here (SPEC §5.7).
	SourceIP func(*http.Request) string

	// ProxyAddress is the IP of the proxy in front of this listener (core.Config.ProxyAddress,
	// deploy/envoy): a request whose connection comes from it carries the caller's certificate
	// chain in X-Forwarded-Client-Cert and the caller's address in X-HDTP-Client-Address, and is
	// judged by them; from any other source both headers are ignored. "" is no proxy.
	ProxyAddress string

	// IgnoreClientCert reports that a presented certificate is the EDGE's, not
	// a caller's, and must not become a transport identity (SPEC §10.1, §10.6).
	// nil means ordinary direct mode, where a certificate IS the caller.
	IgnoreClientCert func() bool
	// Now is the clock a presented chain is judged at; nil is the wall clock. Every other
	// decision in this package already went through one (Identifier.Now, SealedDeps.Now), and
	// the transport read `time.Now()` directly — so under an injected clock the handshake and
	// the envelope could disagree about whether the same leaf had run out.
	Now func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler builds the route mux with facts extraction (SPEC §5.1–§5.2).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/a/{slug}/mcp", s.slugCheck(s.MCP))
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		// Alias exists iff exactly one account (SPEC §5.2).
		slugs := s.Accounts()
		if len(slugs) != 1 {
			http.NotFound(w, r)
			return
		}
		r.SetPathValue("slug", slugs[0])
		s.MCP.ServeHTTP(w, r)
	})
	mux.Handle("/i/{token}", s.Invite)
	if s.Probe != nil {
		mux.Handle(tunnel.ProbePath, s.Probe)
	}

	var h http.Handler = mux
	if s.Inner != nil {
		h = s.Inner(h)
	}
	return s.withFacts(h)
}

// slugCheck 404s unknown accounts before the handler runs.
func (s *Server) slugCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		for _, known := range s.Accounts() {
			if slug == known {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
}

// withFacts extracts TransportFacts from the TLS state into the request context.
func (s *Server) withFacts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := TransportFacts{SrcAddr: r.RemoteAddr}
		fromProxy := s.fromProxy(r)
		switch {
		case fromProxy:
			// The caller's address as the proxy saw it on its own socket; none when it named none,
			// so the caller is budgeted as an address nobody gave rather than as the proxy's.
			if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(ProxyAddressHeader))); ip != nil {
				f.RemoteIP = ip.String()
			}
		case s.SourceIP != nil:
			f.RemoteIP = s.SourceIP(r)
		default:
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				f.RemoteIP = host
			}
		}
		// Behind a TERMINATING edge the only certificate that can arrive is the
		// edge's own — the caller's TLS ended there. Recording it as the caller
		// would make every sealed call fail §5.3's unified identity rule (the
		// transport identity would never equal the envelope signer) and would
		// bucket every caller's rate budget under the edge. The pin on that
		// certificate is a transport check and stops at the handshake.
		if s.IgnoreClientCert != nil && s.IgnoreClientCert() {
			next.ServeHTTP(w, r.WithContext(WithFacts(r.Context(), f)))
			return
		}
		// Only a validated chain is an identity. The retired generation took the
		// fingerprint of whatever single certificate arrived, which is a proof
		// only while the identity IS a key; under 2.0 the identity is the root,
		// a lone certificate names no root, and anyone can mint one in a second.
		// Reading it as identity made `client_cert: required` — the "who may
		// knock at all" posture of HDTP §13.4 — satisfiable by any self-signed
		// certificate, gave a caller a fresh guest budget per certificate, and
		// gave HDTP §2's "both proofs present, their leaf keys MUST match" an
		// unproven key to compare a proven one against.
		var chain [][]byte
		switch {
		case fromProxy:
			// The proxy terminated the caller's TLS: what the caller presented is what the proxy
			// forwarded, and the proxy's own connection carries no certificate of the caller's.
			chain = forwardedChain(r.Header.Values(ProxyCertHeader))
		case r.TLS != nil && len(r.TLS.PeerCertificates) == 2:
			chain = [][]byte{r.TLS.PeerCertificates[0].Raw, r.TLS.PeerCertificates[1].Raw}
		}
		if len(chain) == 2 {
			if vr := hdtpidentity.ValidateChain(chain, hdtpidentity.ChainOpts{Now: s.now()}); vr.OK {
				f.ClientCertFingerprint, f.ClientCertSPKI = vr.RootFingerprint, vr.LeafKey.SPKI
				f.ClientLeaf, f.ClientEndpoint = chain[0], vr.Endpoint
				f.ClientRoot = chain[1]
			}
		}
		next.ServeHTTP(w, r.WithContext(WithFacts(r.Context(), f)))
	})
}

// The two headers a proxy in front of the listener sets (deploy/envoy/envoy.yaml): the caller's
// certificate chain, and the caller's address as the proxy's socket saw it. Envoy replaces
// whatever a caller sent in either (forward_client_cert_details SANITIZE_SET; the address header
// is set from %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% with OVERWRITE_IF_EXISTS_OR_ADD), and the
// node reads them only from ProxyAddress. The address is not Envoy's own
// X-Envoy-External-Address: Envoy passes a caller's value of that one through when it counts the
// caller as internal (internal_address_config), which is a deployment's setting, not this node's.
const (
	ProxyCertHeader    = "X-Forwarded-Client-Cert"
	ProxyAddressHeader = "X-HDTP-Client-Address"
)

// fromProxy reports whether r's connection comes from the configured proxy.
func (s *Server) fromProxy(r *http.Request) bool {
	if s.ProxyAddress == "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer, want := net.ParseIP(host), net.ParseIP(s.ProxyAddress)
	return peer != nil && want != nil && peer.Equal(want)
}

// forwardedChain is the certificate chain an X-Forwarded-Client-Cert names, DER, leaf first: its
// `Chain` member (Envoy's set_current_client_cert_details.chain), URL-encoded PEM. Anything else —
// no header, more than one element (a proxy that appended rather than replaced), no Chain, a Chain
// that does not decode — is no chain at all: the caller then proved nothing on the transport.
func forwardedChain(values []string) [][]byte {
	if len(values) != 1 {
		return nil
	}
	elements := splitOutsideQuotes(values[0], ',')
	if len(elements) != 1 {
		return nil
	}
	for _, pair := range splitOutsideQuotes(elements[0], ';') {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Chain") {
			continue
		}
		unquoted, err := strconv.Unquote(strings.TrimSpace(v))
		if err != nil {
			unquoted = strings.TrimSpace(v)
		}
		decoded, err := url.PathUnescape(unquoted)
		if err != nil {
			return nil
		}
		var chain [][]byte
		rest := []byte(decoded)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil
			}
			chain = append(chain, block.Bytes)
		}
		return chain
	}
	return nil
}

// splitOutsideQuotes splits s at sep where sep is not inside a double-quoted run.
func splitOutsideQuotes(s string, sep rune) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, c := range s {
		switch {
		case c == '"':
			quoted = !quoted
			cur.WriteRune(c)
		case c == sep && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	return append(out, cur.String())
}

// WithFactsForTest exposes the facts middleware so a test can assert what a
// request is seen as, rather than asserting on the flag that decides it.
func (s *Server) WithFactsForTest(next http.Handler) http.Handler { return s.withFacts(next) }

// TLSConfig: RequestClientCert — never Require, never chain-verify. Unknown and
// absent certificates MUST complete the handshake; identity decisions happen above
// the transport (HDTP §2, SPEC §5.1).
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: s.GetCertificate,
	}
}
