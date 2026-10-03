package public

// A proxy in front of the listener (deploy/envoy, SPEC §5.1) terminates the caller's TLS and
// forwards the caller's certificate chain (X-Forwarded-Client-Cert) and address
// (X-HDTP-Client-Address). The node reads them from the configured proxy's connections and from
// no other: the same headers from anybody else are a caller's own claim, and prove nothing.

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// xfcc is the header Envoy writes with set_current_client_cert_details {cert, chain}: the leaf, and
// the chain, each URL-encoded PEM.
func xfcc(chain [][]byte) string {
	var all []byte
	for _, der := range chain {
		all = append(all, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0]})
	return `Hash=00;Cert="` + url.PathEscape(string(leaf)) + `";Chain="` + url.PathEscape(string(all)) + `";Subject="CN=x"`
}

func factsOf(t *testing.T, s *Server, remote string, header http.Header) TransportFacts {
	t.Helper()
	var got TransportFacts
	h := s.WithFactsForTest(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = FactsFrom(r.Context()) }))
	req := httptest.NewRequest("POST", "/a/work/mcp", nil)
	req.RemoteAddr = remote
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestTheProxysForwardedChainAndAddressAreReadFromItAlone(t *testing.T) {
	now := time.Now()
	p := newPeer(t, now)
	s := &Server{ProxyAddress: "10.0.0.2", Now: func() time.Time { return now }}
	forwarded := http.Header{ProxyCertHeader: {xfcc(p.chain())}, ProxyAddressHeader: {"203.0.113.9"}}

	// From the proxy: the caller is the root the forwarded chain proves, at the address the proxy saw.
	got := factsOf(t, s, "10.0.0.2:40000", forwarded)
	if got.ClientCertFingerprint != p.fpr() || !got.ChainProven() || got.RemoteIP != "203.0.113.9" {
		t.Fatalf("from the proxy: caller %q proven %v at %q; want %q, true, 203.0.113.9", got.ClientCertFingerprint, got.ChainProven(), got.RemoteIP, p.fpr())
	}
	// The same headers from anybody else prove nothing, and the address is the socket's.
	got = factsOf(t, s, "198.51.100.7:40000", forwarded)
	if got.ClientCertFingerprint != "" || got.ChainProven() || got.RemoteIP != "198.51.100.7" {
		t.Fatalf("a caller's own forwarded headers were believed: %+v", got)
	}
	// And with no proxy configured, from any address at all.
	got = factsOf(t, &Server{Now: func() time.Time { return now }}, "10.0.0.2:40000", forwarded)
	if got.ClientCertFingerprint != "" || got.RemoteIP != "10.0.0.2" {
		t.Fatalf("with no proxy configured the headers were believed: %+v", got)
	}
	// From the proxy, a caller who presented nothing is anonymous, and one the proxy named no
	// address for is budgeted as no address, never as the proxy's own.
	got = factsOf(t, s, "10.0.0.2:40000", http.Header{})
	if got.ClientCertFingerprint != "" || got.RemoteIP != "" {
		t.Fatalf("from the proxy with nothing forwarded: %+v", got)
	}
}

func TestAForwardedChainThatDoesNotReadProvesNothing(t *testing.T) {
	now := time.Now()
	p := newPeer(t, now)
	s := &Server{ProxyAddress: "10.0.0.2", Now: func() time.Time { return now }}
	lone := [][]byte{p.leaf}
	for name, value := range map[string][]string{
		"two elements (a proxy that appended)": {xfcc(p.chain()) + "," + xfcc(p.chain())},
		"two headers":                          {xfcc(p.chain()), xfcc(p.chain())},
		"no Chain member":                      {`Hash=00;Subject="CN=x"`},
		"a Chain that is not PEM":              {`Chain="not%20a%20certificate"`},
		"a lone certificate":                   {xfcc(lone)},
		"a chain the leaf's root did not sign": {xfcc([][]byte{p.leaf, newPeer(t, now).root.cert})},
	} {
		got := factsOf(t, s, "10.0.0.2:40000", http.Header{ProxyCertHeader: value})
		if got.ClientCertFingerprint != "" || got.ChainProven() {
			t.Errorf("%s: proved %q", name, got.ClientCertFingerprint)
		}
	}
}
