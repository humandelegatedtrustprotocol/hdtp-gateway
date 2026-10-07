package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func keypairCert(t *testing.T, cn string) (*identity.Keypair, tls.Certificate) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, cn)
	if err != nil {
		t.Fatal(err)
	}
	return kp, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
}

// nodeListener is a node's own TLS listener echoing the caller's client-cert
// fingerprint and its own name.
func nodeListener(t *testing.T, name string, cert tls.Certificate) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				seen := "none"
				if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
					seen, _ = identity.Fingerprint(certs[0].PublicKey)
				}
				fmt.Fprintf(tc, "%s peer=%s\n", name, seen)
			}(c)
		}
	}()
	return ln
}

func TestPairingTokenIsSingleUse(t *testing.T) {
	reg := NewMemoryRegistry(nil)
	ingKP, ingCert := keypairCert(t, "ingress")
	ps := &PairingServer{Registry: reg, Domain: "example.test", IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp"}
	srv := httptest.NewUnstartedServer(ps.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()

	tok, _ := reg.MintToken(time.Minute)
	nodeKP, nodeCert := keypairCert(t, "node")
	// pin check: a wrong expected ingress fingerprint aborts before pairing
	if _, _, err := Pair(nil, srv.URL+"/pair", nodeCert, "sha256:not-the-ingress", PairRequest{Token: tok, Subdomain: "a", Mode: ModePassthrough}); err == nil {
		t.Fatal("wrong ingress pin accepted")
	}
	res, seen, err := Pair(nil, srv.URL+"/pair", nodeCert, "", PairRequest{Token: tok, Subdomain: "a", Mode: ModePassthrough})
	if err != nil || res.PublicName != "a.example.test" || res.NodeSecret == "" || seen != ingKP.Fingerprint || res.IngressFingerprint != ingKP.Fingerprint {
		t.Fatalf("pair: %+v seen=%s err=%v", res, seen, err)
	}
	n, ok := reg.BySubdomain("a")
	if !ok || n.Fingerprint != nodeKP.Fingerprint || len(n.SPKI) == 0 {
		t.Fatalf("registry: %+v", n)
	}
	// same token again: refused (exactly once per token)
	if _, _, err := Pair(nil, srv.URL+"/pair", nodeCert, ingKP.Fingerprint, PairRequest{Token: tok, Subdomain: "b", Mode: ModePassthrough}); err == nil || !strings.Contains(err.Error(), "invite_invalid") {
		t.Fatalf("token reuse accepted: %v", err)
	}
	// unknown token refused; no client cert refused
	if _, _, err := Pair(nil, srv.URL+"/pair", nodeCert, "", PairRequest{Token: "pair_nope", Subdomain: "c", Mode: ModePassthrough}); err == nil {
		t.Fatal("unknown token accepted")
	}
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}).Post(srv.URL+"/pair", "application/json", strings.NewReader(`{"token":"x","subdomain":"d","mode":"passthrough"}`))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cert pairing: %v %d", err, resp.StatusCode)
	}
	// a second node cannot take an already-paired subdomain
	tok2, _ := reg.MintToken(time.Minute)
	_, otherCert := keypairCert(t, "other")
	if _, _, err := Pair(nil, srv.URL+"/pair", otherCert, "", PairRequest{Token: tok2, Subdomain: "a", Mode: ModePassthrough}); err == nil {
		t.Fatal("subdomain takeover accepted")
	}
}

// AC: in-process ingress + two nodes — SNI routes each subdomain to the right
// node and the caller's client certificate is visible AT THE NODE through the
// ingress (raw passthrough, the node's own cert served end to end).
func TestSNIPassthroughRoutesAndKeepsClientCertVisible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := NewMemoryRegistry(nil)
	dp := &DataPlane{Registry: reg, Domain: "example.test", BindAddr: "127.0.0.1",
		BindPort: freePort(t), VhostHTTPSPort: freePort(t), Token: "dp-token"}
	if err := dp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer dp.Stop()

	nodes := map[string]struct {
		kp   *identity.Keypair
		cert tls.Certificate
		ln   net.Listener
	}{}
	for _, name := range []string{"alpha", "beta"} {
		kp, cert := keypairCert(t, name)
		ln := nodeListener(t, name, cert)
		tok, _ := reg.MintToken(time.Minute)
		if !reg.ConsumeToken(tok) { // pairing (the HTTP leg is covered above)
			t.Fatal("token")
		}
		spkiNode := Node{Fingerprint: kp.Fingerprint, SPKI: []byte{1}, Subdomain: name, Mode: ModePassthrough, Secret: "secret-" + name}
		if err := reg.Put(spkiNode); err != nil {
			t.Fatal(err)
		}
		nodes[name] = struct {
			kp   *identity.Keypair
			cert tls.Certificate
			ln   net.Listener
		}{kp, cert, ln}
		// the node's reverse tunnel: the frp adapter in https (SNI) mode with its pairing credentials
		a, err := tunnel.New("frp", tunnel.Options{PublicBind: ln.Addr().String(), Extra: map[string]string{
			"server_addr": "127.0.0.1", "server_port": strconv.Itoa(dp.BindPort), "token": "dp-token",
			"proxy_type": "https", "custom_domain": name + ".example.test", "name": name,
			"meta_" + MetaNode: kp.Fingerprint, "meta_" + MetaSecret: "secret-" + name,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer a.Stop()
	}

	callerKP, callerCert := keypairCert(t, "caller")
	dial := func(sni string, wait time.Duration) (string, error) {
		var last error
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			conn, err := tls.Dial("tcp", net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort)), &tls.Config{
				ServerName: sni, InsecureSkipVerify: true, Certificates: []tls.Certificate{callerCert}, MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				last = err
				time.Sleep(200 * time.Millisecond)
				continue
			}
			b, _ := io.ReadAll(conn)
			conn.Close()
			if len(b) == 0 {
				last = fmt.Errorf("empty answer")
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return strings.TrimSpace(string(b)), nil
		}
		return "", last
	}
	for _, name := range []string{"alpha", "beta"} {
		got, err := dial(name+".example.test", 15*time.Second)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != name+" peer="+callerKP.Fingerprint {
			t.Fatalf("SNI %s reached %q (want node %s with caller cert %s)", name, got, name, callerKP.Fingerprint)
		}
	}
	// an unpaired subdomain routes nowhere
	if _, err := dial("gamma.example.test", 2*time.Second); err == nil {
		t.Fatal("unpaired subdomain served")
	}
	// an unpaired node (bad secret) cannot even log in to the data plane
	badKP, badCert := keypairCert(t, "bad")
	badLn := nodeListener(t, "bad", badCert)
	bad, _ := tunnel.New("frp", tunnel.Options{PublicBind: badLn.Addr().String(), Extra: map[string]string{
		"server_addr": "127.0.0.1", "server_port": strconv.Itoa(dp.BindPort), "token": "dp-token",
		"proxy_type": "https", "custom_domain": "alpha.example.test", "name": "hijack",
		"meta_" + MetaNode: badKP.Fingerprint, "meta_" + MetaSecret: "wrong",
	}})
	if _, err := bad.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer bad.Stop()
	time.Sleep(1500 * time.Millisecond) // let the hijack attempt be refused
	if got, err := dial("alpha.example.test", 5*time.Second); err != nil || !strings.HasPrefix(got, "alpha ") {
		t.Fatalf("alpha hijacked or lost: %q %v", got, err)
	}
}

// AC (P10-06b): pairing in terminate mode announces the name, so the ingress can
// obtain a certificate for it.
//
// Nothing ever told certmagic WHICH names to manage, so its GetCertificate had
// nothing to answer with and every terminate handshake failed — silently, because
// the failure is inside the TLS handshake and never reaches a handler. The tests
// hid it by calling acme.Manage themselves, which is not something the product
// did anywhere.
func TestTerminatePairingAnnouncesItsNameForACertificate(t *testing.T) {
	reg := NewMemoryRegistry(nil)
	ingKP, ingCert := keypairCert(t, "ingress")

	var managed []string
	ps := &PairingServer{
		Registry: reg, Domain: "example.test", IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp",
		OnPaired: func(n Node) {
			if n.Mode == ModeTerminate {
				managed = append(managed, n.Subdomain)
			}
		},
	}
	srv := httptest.NewUnstartedServer(ps.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()

	_, nodeCert := keypairCert(t, "node")
	tok, _ := reg.MintToken(time.Minute)
	if _, _, err := Pair(nil, srv.URL+"/pair", nodeCert, "", PairRequest{
		Token: tok, Subdomain: "term", Mode: ModeTerminate,
	}); err != nil {
		t.Fatal(err)
	}
	if len(managed) != 1 || managed[0] != "term" {
		t.Fatalf("a terminate pairing did not announce its name: %v", managed)
	}

	// A passthrough pairing needs no certificate here: the node terminates its
	// own TLS and the ingress only routes by SNI (§10.6).
	tok2, _ := reg.MintToken(time.Minute)
	if _, _, err := Pair(nil, srv.URL+"/pair", nodeCert, "", PairRequest{
		Token: tok2, Subdomain: "pass", Mode: ModePassthrough,
	}); err != nil {
		t.Fatal(err)
	}
	if len(managed) != 1 {
		t.Fatalf("a passthrough pairing asked for a certificate: %v", managed)
	}
}

// AC: the data plane can be stopped the moment it is started (the ingress
// command defers Stop, so a failure right after Start does exactly that), and
// Stop releases its ports. frp v0.71.0's server Close read the cancel func Run
// sets on its own goroutine — a data race this test fails on under -race
// (third_party/frp.patch).
func TestDataPlaneStopRightAfterStart(t *testing.T) {
	dp := &DataPlane{Registry: NewMemoryRegistry(nil), Domain: "example.test", BindAddr: "127.0.0.1", BindPort: freePort(t), VhostHTTPSPort: freePort(t), Token: "dp"}
	if err := dp.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dp.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{dp.BindPort, dp.VhostHTTPSPort} {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("port %d still held after Stop: %v", port, err)
		}
		_ = l.Close()
	}
}
