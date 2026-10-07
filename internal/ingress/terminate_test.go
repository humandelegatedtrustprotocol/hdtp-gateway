package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// stubDNS answers every A query with 127.0.0.1 so Pebble's validator reaches
// the in-process HTTP-01 responder for names under example.test.
func stubDNS(t *testing.T) string {
	t.Helper()
	// Pebble's custom resolver speaks TCP; serve the same handler on both.
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			case dns.TypeCAA, dns.TypeAAAA, dns.TypeTXT:
				// empty NOERROR
			}
		}
		_ = w.WriteMsg(m)
	})
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: tl, Handler: handler}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return tl.Addr().String()
}

// pebbleCA runs Pebble in-process: an ACME directory over HTTPS whose HTTP-01
// validator dials httpPort on the resolved (stubbed) address.
func pebbleCA(t *testing.T, httpPort int, resolver string) (dirURL string, trust *x509.CertPool) {
	t.Helper()
	// Pebble deliberately rejects 5% of good nonces by default (chaos for
	// clients); the test wants deterministic issuance.
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	logger := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	// Pebble picks a random profile per order: it needs at least one.
	caImpl := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default", ValidityPeriod: 90 * 24 * 3600},
	})
	vaImpl := va.New(logger, httpPort, 0, false, resolver, store)
	w := wfe.New(logger, store, vaImpl, caImpl, nil, false, false, 3, 5)
	srv := httptest.NewTLSServer(w.Handler())
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())                  // the directory's own HTTPS cert
	pool.AddCert(caImpl.GetRootCert(0).Cert)         // the issuing root, for callers
	pool.AddCert(caImpl.GetIntermediateCert(0).Cert) // and its intermediate
	return srv.URL + wfe.DirectoryPath, pool
}

// AC: Pebble issues the public certificate and the renewal path works.
func TestACMEIssuanceAndRenewalWithPebble(t *testing.T) {
	resolver := stubDNS(t)
	httpPort := freePort(t)
	dir, trust := pebbleCA(t, httpPort, resolver)
	acme, err := NewACME(ACMEOptions{
		StorageDir: t.TempDir(), CA: dir, Email: "owner@example.test", TrustedRoots: trust,
		HTTP01Port: httpPort, ListenHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := acme.Manage(ctx, "alpha.example.test"); err != nil {
		t.Fatalf("issuance: %v", err)
	}
	cfg := acme.TLSConfig()
	cert1, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.example.test"})
	if err != nil || cert1 == nil || cert1.Leaf == nil || cert1.Leaf.Subject.CommonName != "alpha.example.test" && len(cert1.Leaf.DNSNames) == 0 {
		t.Fatalf("no served cert: %v", err)
	}
	if err := acme.Renew(ctx, "alpha.example.test"); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	cert2, _ := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.example.test"})
	if cert2 == nil || cert2.Leaf.SerialNumber.Cmp(cert1.Leaf.SerialNumber) == 0 {
		t.Fatal("renewal did not rotate the certificate")
	}
}

// AC: a sealed call round-trips through terminate mode (public ACME TLS at the
// ingress → fresh mutually-pinned mTLS to the node over its reverse tunnel),
// and the onward leg refuses a node whose key is not the pinned one.
func TestTerminateModeRoundTripsSealedCallAndRefusesUnpinnedNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	resolver := stubDNS(t)
	httpPort := freePort(t)
	dir, trust := pebbleCA(t, httpPort, resolver)
	acme, err := NewACME(ACMEOptions{StorageDir: t.TempDir(), CA: dir, TrustedRoots: trust, HTTP01Port: httpPort, ListenHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := acme.Manage(ctx, "alpha.example.test"); err != nil {
		t.Fatalf("issuance: %v", err)
	}

	// ingress identity + data plane
	ingKP, ingCert := keypairCert(t, "ingress")
	reg := NewMemoryRegistry(nil)
	dp := &DataPlane{Registry: reg, Domain: "example.test", BindAddr: "127.0.0.1", BindPort: freePort(t), VhostHTTPSPort: freePort(t), Token: "dp"}
	if err := dp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer dp.Stop()

	// the node: identity keypair, onward-leg listener pinning the ingress,
	// reverse tunnel under its INTERNAL name, paired in terminate mode
	nodeKP, nodeCert := keypairCert(t, "node")
	nodeSPKI, _ := x509.MarshalPKIXPublicKey(nodeKP.Signer.Public())
	nodePKCS8, _ := x509.MarshalPKCS8PrivateKey(nodeKP.Signer)
	if err := reg.Put(Node{Fingerprint: nodeKP.Fingerprint, SPKI: nodeSPKI, Subdomain: "alpha", Mode: ModeTerminate, Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	nodeLn, err := tls.Listen("tcp", "127.0.0.1:0", pinnedNodeConfig(nodeCert, ingKP.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	defer nodeLn.Close()
	go func() { // the node opens sealed envelopes it receives and echoes the plaintext
		for {
			c, err := nodeLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var env hdtpidentity.Envelope
				if err := json.NewDecoder(c).Decode(&env); err != nil {
					fmt.Fprintf(c, "decode: %v", err)
					return
				}
				nodePriv, perr := hdtpidentity.ParsePKCS8(nodePKCS8)
				if perr != nil {
					fmt.Fprintf(c, "key: %v", perr)
					return
				}
				suite, serr := hdtpidentity.SuiteForKey(nodePriv.Public())
				if serr != nil {
					fmt.Fprintf(c, "suite: %v", serr)
					return
				}
				protected, errP := hdtpidentity.DecodeB64url(env.Protected)
				enc, errE := hdtpidentity.DecodeB64url(env.Enc)
				ct, errC := hdtpidentity.DecodeB64url(env.Ct)
				if errP != nil || errE != nil || errC != nil {
					fmt.Fprint(c, "decode: the envelope is not base64url")
					return
				}
				plain, err := hdtpidentity.Open(suite, nodePriv, nodePriv.Public(),
					[]byte(hdtpidentity.Info), protected, enc, ct)
				if err != nil {
					fmt.Fprintf(c, "open: %v", err)
					return
				}
				fmt.Fprintf(c, "opened:%s", plain)
			}(c)
		}
	}()
	rev, err := tunnel.New("frp", tunnel.Options{PublicBind: nodeLn.Addr().String(), Extra: map[string]string{
		"server_addr": "127.0.0.1", "server_port": strconv.Itoa(dp.BindPort), "token": "dp",
		"proxy_type": "https", "custom_domain": InternalName("alpha", "example.test"), "name": "alpha-internal",
		"meta_" + MetaNode: nodeKP.Fingerprint, "meta_" + MetaSecret: "s",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rev.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer rev.Stop()

	// the terminator on the public port
	pubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	term := &Terminator{Registry: reg, Domain: "example.test", Public: acme.TLSConfig(), IngressCert: ingCert, DataPlaneAddr: net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort))}
	go term.Serve(pubLn)
	defer term.Close()

	// A caller seals a call to the node's key and sends it through the public name.
	// What this proves is that a SEALED payload survives a terminating edge intact —
	// which is the whole reason sealing exists (HDTP §13) — so the envelope is built
	// from the library's primitives.
	nodePub, err := hdtpidentity.ParseSPKI(nodeSPKI)
	if err != nil {
		t.Fatal(err)
	}
	protected := []byte(`{"cty":"application/hdtp-call+json","v":1}`)
	suite, err := hdtpidentity.SuiteForKey(nodePub)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hdtpidentity.Seal(suite, nodePub,
		[]byte(hdtpidentity.Info), protected, []byte(`{"tool":"send_message"}`))
	if err != nil {
		t.Fatal(err)
	}
	env := &hdtpidentity.Envelope{Protected: hdtpidentity.B64url(protected), Enc: hdtpidentity.B64url(enc), Ct: hdtpidentity.B64url(ct), Sig: hdtpidentity.B64url([]byte("sig"))}
	body, _ := json.Marshal(env)
	var reply string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", pubLn.Addr().String(), &tls.Config{ServerName: "alpha.example.test", RootCAs: trust, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatalf("public TLS (ACME cert must validate): %v", err)
		}
		_, _ = conn.Write(body)
		_ = conn.CloseWrite()
		b, _ := io.ReadAll(conn)
		conn.Close()
		reply = string(b)
		if strings.HasPrefix(reply, "opened:") {
			break
		}
		time.Sleep(300 * time.Millisecond) // the reverse tunnel may still be registering
	}
	if reply != `opened:{"tool":"send_message"}` {
		t.Fatalf("sealed call did not round-trip: %q", reply)
	}

	// refusal: the registry pins a DIFFERENT key for alpha → the onward leg must fail
	otherKP, _ := identity.Generate(identity.AlgoP256)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(otherKP.Signer.Public())
	if _, err := term.DialNode(ctx, Node{Fingerprint: otherKP.Fingerprint, SPKI: otherSPKI, Subdomain: "alpha", Mode: ModeTerminate}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("unpinned node accepted on the onward leg: %v", err)
	}
	// and the node refuses anything that is not the paired ingress
	_, strangerCert := keypairCert(t, "stranger")
	if c, err := tls.Dial("tcp", nodeLn.Addr().String(), &tls.Config{Certificates: []tls.Certificate{strangerCert}, InsecureSkipVerify: true}); err == nil {
		if _, err := c.Write([]byte("x")); err == nil {
			if _, err := io.ReadAll(c); err == nil {
				t.Fatal("node accepted a non-ingress client on the onward leg")
			}
		}
		c.Close()
	}
	_ = http.StatusOK
}

// Every real client offers ALPN. certmagic's TLSConfig sets NextProtos to
// acme-tls/1 ALONE — its own comment says the field is there "for TLS-ALPN
// challenge", i.e. it is meant to be MERGED into a server config, not served as
// one — and ACME.TLSConfig handed it straight through to Terminator.Public() and
// tls.Server. So the terminate listener advertised only the challenge protocol
// and answered every browser, curl and Go client with no_application_protocol.
// SPEC §10.6 says a terminate-mode node is reachable at plain
// https://name.domain; it was reachable by nothing that speaks ALPN.
//
// The existing in-process tests could not see it: they dial with a hand-built
// tls.Config carrying no NextProtos, so no ALPN extension is sent and the server
// never enforces one. This test dials the way curl does.
func TestTerminatePublicTLSAcceptsAClientThatOffersALPN(t *testing.T) {
	a, err := NewACME(ACMEOptions{StorageDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	_, cert := keypairCert(t, "alpha.example.test")
	cfg := a.TLSConfig()
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }

	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	server := tls.Server(sc, cfg)
	client := tls.Client(cc, &tls.Config{
		ServerName:         "alpha.example.test",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		// exactly what curl and every browser offer
		NextProtos: []string{"h2", "http/1.1"},
	})
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	cerr := client.Handshake()
	serr := <-errc
	if cerr != nil || serr != nil {
		t.Fatalf("a client offering ALPN could not complete the handshake (client: %v, server: %v) "+
			"— terminate mode is unreachable by any real HTTPS client", cerr, serr)
	}
	// http/1.1 and not h2: the terminator SPLICES the decrypted stream into a
	// separate TLS leg to the node, which negotiates its own ALPN and serves
	// HTTP/1.1. Advertising h2 out front would have the caller send HTTP/2 frames
	// into an HTTP/1.1 server.
	if got := client.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1", got)
	}
}

// pinnedNodeConfig is a node listener's config with the onward-leg pin the node installs.
func pinnedNodeConfig(cert tls.Certificate, ingressFingerprint string) *tls.Config {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	PinOnwardLeg(cfg, ingressFingerprint, nil)
	return cfg
}
