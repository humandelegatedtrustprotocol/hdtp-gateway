// Package public implements the PACT-facing surface (SPEC §5): the TLS listener,
// transport-fact extraction, and the route shell. Tiering, per-caller servers, and
// dispatch land in later tasks; this file owns everything at and below the connection.
package public

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/tunnel"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// TransportFacts is what the transport layer proved about a request (SPEC §5.1).
// The certificate fingerprint here is a FACT, not an authorization: tiering and the
// unified identity rule (§3.5) are applied above.
type TransportFacts struct {
	ClientCertFingerprint string // "" when no certificate was presented
	// ClientCertSPKI is the presented key itself (SubjectPublicKeyInfo DER).
	// Pinning stores the full key, never just its hash (§9.2), so the plaintext
	// mTLS path must carry it exactly as the sealed path carries `spk`.
	ClientCertSPKI []byte
	// RemoteIP is the source address the node trusts for this request: the
	// adapter's own header behind a terminating edge, the socket otherwise, and
	// never a generic forwarded-for header (SPEC §5.7). Guest budgets key on it.
	RemoteIP string
	SrcAddr  string
	// PACT 2.0 (PACT §2, §14.2): a client that presented a chain — a leaf and
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
// only thing that establishes an identity at the transport (PACT §2, §14.2). The fields above
// are filled together by that one event or not at all, so the leaf's presence is the fact; a
// `ClientProtocol` field used to sit beside them saying 2 exactly when it was there.
func (f TransportFacts) ChainProven() bool { return len(f.ClientLeaf) > 0 }

type factsKey struct{}

func FactsFrom(ctx context.Context) TransportFacts {
	f, _ := ctx.Value(factsKey{}).(TransportFacts)
	return f
}

// WithFacts attaches transport facts to a context. The listener does this per
// request; it is exported so an in-process caller (the relay fetch loop, tests)
// can present the same facts the wire would have carried.
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

	// IgnoreClientCert reports that a presented certificate is the EDGE's, not
	// a caller's, and must not become a transport identity (SPEC §10.1, §10.6).
	// nil means ordinary direct mode, where a certificate IS the caller.
	IgnoreClientCert func() bool
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
		if s.SourceIP != nil {
			f.RemoteIP = s.SourceIP(r)
		} else if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			f.RemoteIP = host
		}
		// Behind a TERMINATING edge the only certificate that can arrive is the
		// edge's own — the caller's TLS ended there. Recording it as the caller
		// would make every sealed call fail §5.3's unified identity rule (the
		// transport identity would never equal the envelope signer) and would
		// bucket every caller's rate budget under the edge. The pin on that
		// certificate is a transport check and stops at the handshake.
		if s.IgnoreClientCert != nil && s.IgnoreClientCert() {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), factsKey{}, f)))
			return
		}
		// Only a validated chain is an identity. The retired generation took the
		// fingerprint of whatever single certificate arrived, which is a proof
		// only while the identity IS a key; under 2.0 the identity is the root,
		// a lone certificate names no root, and anyone can mint one in a second.
		// Reading it as identity made `client_cert: required` — the "who may
		// knock at all" posture of PACT §13.4 — satisfiable by any self-signed
		// certificate, gave a caller a fresh guest budget per certificate, and
		// gave PACT §2's "both proofs present, their leaf keys MUST match" an
		// unproven key to compare a proven one against.
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 2 {
			chain := [][]byte{r.TLS.PeerCertificates[0].Raw, r.TLS.PeerCertificates[1].Raw}
			if vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: time.Now()}); vr.OK {
				f.ClientCertFingerprint, f.ClientCertSPKI = vr.RootFingerprint, vr.LeafKey.SPKI
				f.ClientLeaf, f.ClientEndpoint = chain[0], vr.Endpoint
				f.ClientRoot = chain[1]
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), factsKey{}, f)))
	})
}

// WithFactsForTest exposes the facts middleware so a test can assert what a
// request is seen as, rather than asserting on the flag that decides it.
func (s *Server) WithFactsForTest(next http.Handler) http.Handler { return s.withFacts(next) }

// TLSConfig: RequestClientCert — never Require, never chain-verify. Unknown and
// absent certificates MUST complete the handshake; identity decisions happen above
// the transport (PACT §2, SPEC §5.1).
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: s.GetCertificate,
	}
}
