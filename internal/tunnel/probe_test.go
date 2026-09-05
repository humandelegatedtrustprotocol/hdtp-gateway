package tunnel

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// listener is a self-signed TLS server the way a node serves its public
// surface: the served leaf carries an identity keypair.
func listener(t *testing.T, instance string, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, "node")
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = ProbeHandler(instance)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: kp.Signer}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, kp.Fingerprint
}

func TestProbeVerdicts(t *testing.T) {
	ctx := context.Background()
	srv, fpr := listener(t, "node-A", nil)

	// reachable: right pin, nonce echoed, same instance
	r := Probe(ctx, srv.URL, ProbeOptions{PinnedFingerprint: fpr, InstanceID: "node-A", Timeout: 3 * time.Second})
	if r.Verdict != VerdictReachable {
		t.Fatalf("reachable: %+v", r)
	}
	// wrong cert: a different pin
	other, _ := identity.Generate(identity.AlgoP256)
	r = Probe(ctx, srv.URL, ProbeOptions{PinnedFingerprint: other.Fingerprint, InstanceID: "node-A", Timeout: 3 * time.Second})
	if r.Verdict != VerdictWrongCert {
		t.Fatalf("wrong cert: %+v", r)
	}
	// wrong cert via WebPKI: a self-signed leaf never validates without a pin
	r = Probe(ctx, srv.URL, ProbeOptions{Timeout: 3 * time.Second})
	if r.Verdict != VerdictWrongCert {
		t.Fatalf("webpki on self-signed: %+v", r)
	}
	// wrong instance: the endpoint reaches some OTHER pact-gateway
	r = Probe(ctx, srv.URL, ProbeOptions{PinnedFingerprint: fpr, InstanceID: "node-B", Timeout: 3 * time.Second})
	if r.Verdict != VerdictWrongInstance {
		t.Fatalf("wrong instance: %+v", r)
	}
	// wrong instance: something that is not a node answers there
	web, fprW := listener(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) }))
	r = Probe(ctx, web.URL, ProbeOptions{PinnedFingerprint: fprW, Timeout: 3 * time.Second})
	if r.Verdict != VerdictWrongInstance {
		t.Fatalf("non-node endpoint: %+v", r)
	}
	// unreachable: nothing listens
	srv.Close()
	r = Probe(ctx, srv.URL, ProbeOptions{PinnedFingerprint: fpr, Timeout: 2 * time.Second})
	if r.Verdict != VerdictUnreachable {
		t.Fatalf("unreachable: %+v", r)
	}
	// self-originated probes always carry the hairpin caveat, even on success
	r2, fprC := listener(t, "node-C", nil)
	res := Probe(ctx, r2.URL, ProbeOptions{PinnedFingerprint: fprC, InstanceID: "node-C", SelfOriginated: true, Timeout: 3 * time.Second})
	if res.Verdict != VerdictReachable || res.Caveat == "" {
		t.Fatalf("self-originated: %+v", res)
	}
}

func TestDirectAdapterAndRegistry(t *testing.T) {
	if _, err := New("direct", Options{}); err == nil {
		t.Fatal("direct without public_url accepted")
	}
	a, err := New("direct", Options{PublicURL: "https://pact.example:8443"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Start(context.Background())
	if err != nil || info.TerminatesAtEdge || info.PublicURL != "https://pact.example:8443" {
		t.Fatalf("start: %+v %v", info, err)
	}
	if st := a.Status(); !st.Running || st.Name != "direct" {
		t.Fatalf("status: %+v", st)
	}
	if err := a.Stop(); err != nil || a.Status().Running {
		t.Fatal("stop")
	}
	if edge, err := TerminatesAtEdge("direct"); err != nil || edge {
		t.Fatal("direct must not terminate at an edge")
	}
	if _, err := New("carrier-pigeon", Options{}); err == nil {
		t.Fatal("unknown adapter constructed")
	}
}
