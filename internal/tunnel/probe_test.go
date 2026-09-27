package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// served is a node as it serves its public surface: the chain its owner's wallet issued, leaf then
// root, for the address its leaf names — which is a NAME, because no wallet issues a leaf for a
// loopback address, so the probe is pointed at the name and a resolver sends it to the listener.
type served struct {
	srv      *httptest.Server
	wallet   *testid.Wallet
	host     *testid.Host
	base     string // https://<name>, what the probe is given
	identity Served
}

func (s *served) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, s.srv.Listener.Addr().String())
}

func serve(t *testing.T, name, instance string, h http.Handler) *served {
	t.Helper()
	w := testid.NewWallet(t, name)
	base := "https://" + strings.ToLower(name) + ".example.test"
	host := w.Issue(t, base+"/a/"+strings.ToLower(name)+"/mcp")
	kp, err := identity.FromLib(host.Key)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = ProbeHandler(instance)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: host.Chain, PrivateKey: kp.Signer}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &served{srv: srv, wallet: w, host: host, base: base, identity: Served{Root: w.Fpr, Endpoint: host.Endpoint}}
}

func TestProbeVerdicts(t *testing.T) {
	ctx := context.Background()
	a := serve(t, "Alina", "node-A", nil)
	opts := func(s *served, ids ...Served) ProbeOptions {
		return ProbeOptions{Identities: ids, InstanceID: "node-A", Timeout: 3 * time.Second, DialContext: s.dial}
	}

	// reachable: the chain validates to a root this node serves, at that account's address
	if r := Probe(ctx, a.base, opts(a, a.identity)); r.Verdict != VerdictReachable {
		t.Fatalf("reachable: %+v", r)
	}
	// …and a listener presents ONE chain however many accounts share it: any served identity will do
	other := testid.NewWallet(t, "Bharat")
	if r := Probe(ctx, a.base, opts(a, Served{Root: other.Fpr, Endpoint: "https://alina.example.test/a/bharat/mcp"}, a.identity)); r.Verdict != VerdictReachable {
		t.Fatalf("one of several identities: %+v", r)
	}
	// wrong cert: the chain is somebody else's
	if r := Probe(ctx, a.base, opts(a, Served{Root: other.Fpr, Endpoint: a.identity.Endpoint})); r.Verdict != VerdictWrongCert {
		t.Fatalf("another root: %+v", r)
	}
	// wrong cert via WebPKI: with no identity to validate against, a person's chain is not publicly trusted
	if r := Probe(ctx, a.base, opts(a)); r.Verdict != VerdictWrongCert {
		t.Fatalf("webpki on a person's chain: %+v", r)
	}
	// wrong instance: the endpoint reaches some OTHER pact-gateway
	wrong := opts(a, a.identity)
	wrong.InstanceID = "node-B"
	if r := Probe(ctx, a.base, wrong); r.Verdict != VerdictWrongInstance {
		t.Fatalf("wrong instance: %+v", r)
	}
	// wrong instance: something that is not a node answers there
	web := serve(t, "Web", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello")) }))
	if r := Probe(ctx, web.base, ProbeOptions{Identities: []Served{web.identity}, Timeout: 3 * time.Second, DialContext: web.dial}); r.Verdict != VerdictWrongInstance {
		t.Fatalf("non-node endpoint: %+v", r)
	}
	// self-originated probes always carry the hairpin caveat, even on success
	self := opts(a, a.identity)
	self.SelfOriginated = true
	if r := Probe(ctx, a.base, self); r.Verdict != VerdictReachable || r.Caveat == "" {
		t.Fatalf("self-originated: %+v", r)
	}
	// unreachable: nothing listens
	a.srv.Close()
	if r := Probe(ctx, a.base, ProbeOptions{Identities: []Served{a.identity}, Timeout: 2 * time.Second, DialContext: a.dial}); r.Verdict != VerdictUnreachable {
		t.Fatalf("unreachable: %+v", r)
	}
}

// The case the probe exists to catch, and the one it could not while it pinned a KEY.
//
// A node is moved to a new public URL, or the URL is mistyped, and its leaf goes on naming the old
// address. It serves the right key under the right root — and every peer refuses it, because a
// chain is validated at the address that was DIALLED (PACT §14.2 rule 5). A probe that compares
// key fingerprints passes this node; it did, for as long as the probe kept 1.x's rule. The
// diagnosis has to be the one a peer would make, and it has to say which rule.
func TestProbeRefusesALeafThatNamesAnotherAddress(t *testing.T) {
	ctx := context.Background()
	a := serve(t, "Alina", "node-A", nil)
	// The node believes it answers somewhere its leaf does not name.
	believed := Served{Root: a.wallet.Fpr, Endpoint: "https://moved.example.test/a/alina/mcp"}
	r := Probe(ctx, "https://moved.example.test", ProbeOptions{Identities: []Served{believed}, InstanceID: "node-A", Timeout: 3 * time.Second, DialContext: a.dial})
	if r.Verdict != VerdictWrongCert {
		t.Fatalf("a leaf naming another address passed the probe: %+v", r)
	}
	if !strings.Contains(r.Detail, "rule 5") {
		t.Fatalf("the diagnosis must name the rule a peer would refuse it by: %q", r.Detail)
	}
}

// A lone self-signed certificate is not a chain, whatever key it carries: this is what the probe
// used to ACCEPT, when the key matched.
func TestProbeRefusesALoneSelfSignedCertificate(t *testing.T) {
	ctx := context.Background()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, "node")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(ProbeHandler("node-A"))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: kp.Signer}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}
	w := testid.NewWallet(t, "Alina")
	r := Probe(ctx, "https://alina.example.test", ProbeOptions{
		Identities: []Served{{Root: w.Fpr, Endpoint: "https://alina.example.test/a/alina/mcp"}}, Timeout: 3 * time.Second, DialContext: dial,
	})
	if r.Verdict != VerdictWrongCert || !strings.Contains(r.Detail, "presents its chain") {
		t.Fatalf("a lone certificate: %+v", r)
	}
}
