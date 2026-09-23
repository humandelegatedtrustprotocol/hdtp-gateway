package integrationtest

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

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/ingress"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
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

// stubResolver answers every A query with 127.0.0.1 (TCP+UDP) for Pebble.
func stubResolver(t *testing.T) string {
	t.Helper()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			}
		}
		_ = w.WriteMsg(m)
	})
	u, tc := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: tl, Handler: h}
	go func() { _ = u.ActivateAndServe() }()
	go func() { _ = tc.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.Shutdown(); _ = tc.Shutdown() })
	return tl.Addr().String()
}

func pebble(t *testing.T, httpPort int, resolver string) (string, *x509.CertPool) {
	t.Helper()
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	logger := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	caImpl := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {Description: "default", ValidityPeriod: 90 * 24 * 3600}})
	vaImpl := va.New(logger, httpPort, 0, false, resolver, store)
	w := wfe.New(logger, store, vaImpl, caImpl, nil, false, false, 3, 5)
	srv := httptest.NewTLSServer(w.Handler())
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	pool.AddCert(caImpl.GetRootCert(0).Cert)
	pool.AddCert(caImpl.GetIntermediateCert(0).Cert)
	return srv.URL + wfe.DirectoryPath, pool
}

// nodeBehindIngress is a node's REAL public listener (public.Server: own TLS,
// client certs requested, probe route) fronted through the ingress via the
// ingress-* adapter the pairing response selects.
type nodeBehindIngress struct {
	kp       *identity.Keypair
	cert     tls.Certificate
	instance string
	bind     string
}

func startNode(t *testing.T, ctx context.Context, name string, onwardPin string) *nodeBehindIngress {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := identity.SelfSignedCert(kp, name)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	handler := http.NewServeMux()
	handler.Handle(tunnel.ProbePath, tunnel.ProbeHandler(name))
	handler.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		seen := "none"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			seen, _ = identity.Fingerprint(r.TLS.PeerCertificates[0].PublicKey)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"node": name, "peer": seen})
	})
	var cfg *tls.Config
	if onwardPin != "" {
		// terminate mode: only the paired ingress may deliver traffic
		cfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		ingress.PinOnwardLeg(cfg, onwardPin, nil)
	} else {
		cfg = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	}
	srv := &http.Server{Handler: handler, TLSConfig: cfg}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &nodeBehindIngress{kp: kp, cert: cert, instance: name, bind: ln.Addr().String()}
}

// P5 exit (PLAN P5-05): one in-process ingress fronts two nodes on its domain —
// alpha in PASSTHROUGH (callers' client certs reach alpha end to end, alpha's
// own certificate is served) and beta in TERMINATE (public ACME cert at the
// ingress, fresh mutually-pinned mTLS to beta) — after both paired with
// one-time tokens and derived their modes from the adapter the pairing chose.
func TestP5ExitOwnDomainPassthroughAndTerminate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	const domain = "example.test"

	// --- the ingress on the "VPS" ---
	ingKP, _ := identity.Generate(identity.AlgoP256)
	ingDER, _ := identity.SelfSignedCert(ingKP, "ingress")
	ingCert := tls.Certificate{Certificate: [][]byte{ingDER}, PrivateKey: ingKP.Signer}
	reg := ingress.NewMemoryRegistry(nil)
	dp := &ingress.DataPlane{Registry: reg, Domain: domain, BindAddr: "127.0.0.1", BindPort: freePort(t), VhostHTTPSPort: freePort(t), Token: "dp"}
	if err := dp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer dp.Stop()
	pairing := &ingress.PairingServer{Registry: reg, Domain: domain, IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: dp.BindPort, DataPlaneToken: "dp"}
	pairSrv := httptest.NewUnstartedServer(pairing.Handler())
	pairSrv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	pairSrv.StartTLS()
	defer pairSrv.Close()

	// --- two home nodes pair, each with its own one-time token ---
	alpha := startNode(t, ctx, "alpha", "")
	beta := startNode(t, ctx, "beta", ingKP.Fingerprint)
	pair := func(n *nodeBehindIngress, sub string, mode ingress.Mode) ingress.PairResponse {
		tok, _ := reg.MintToken(time.Minute)
		res, seen, err := ingress.Pair(nil, pairSrv.URL+"/pair", n.cert, "", ingress.PairRequest{Token: tok, Subdomain: sub, Mode: mode})
		if err != nil || seen != ingKP.Fingerprint {
			t.Fatalf("pair %s: %v", sub, err)
		}
		return res
	}
	alphaPair := pair(alpha, "alpha", ingress.ModePassthrough)
	betaPair := pair(beta, "beta", ingress.ModeTerminate)

	// the adapter the pairing selects derives the mode (SPEC §10.1/§10.6)
	adapterFor := func(n *nodeBehindIngress, res ingress.PairResponse, mode ingress.Mode) tunnel.Adapter {
		name := "ingress-passthrough"
		if mode == ingress.ModeTerminate {
			name = "ingress-terminate"
		}
		a, err := tunnel.New(name, tunnel.Options{PublicBind: n.bind, Extra: map[string]string{
			"subdomain": strings.TrimSuffix(res.PublicName, "."+domain), "domain": res.Domain,
			"data_plane_addr": res.DataPlaneAddr, "data_plane_port": strconv.Itoa(res.DataPlanePort),
			"data_plane_token": res.DataPlaneToken, "node_fpr": n.kp.Fingerprint, "node_secret": res.NodeSecret,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return a
	}
	_ = adapterFor(alpha, alphaPair, ingress.ModePassthrough)
	_ = adapterFor(beta, betaPair, ingress.ModeTerminate)
	if derived, err := core.Load("", func(k string) (string, bool) {
		v, ok := map[string]string{"PACT_DATA_DIR": t.TempDir(), "PACT_TUNNEL": "ingress-terminate"}[k]
		return v, ok
	}); err != nil || derived.Mode != core.ModeEdge {
		t.Fatalf("terminate pairing must derive edge mode: %v", err)
	}

	// --- the terminate front: ACME (Pebble) certificate for beta.example.test ---
	resolver := stubResolver(t)
	httpPort := freePort(t)
	dir, trust := pebble(t, httpPort, resolver)
	acme, err := ingress.NewACME(ingress.ACMEOptions{StorageDir: t.TempDir(), CA: dir, TrustedRoots: trust, HTTP01Port: httpPort, ListenHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer acme.Close()
	if err := acme.Manage(ctx, "beta."+domain); err != nil {
		t.Fatalf("acme: %v", err)
	}
	pubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	term := &ingress.Terminator{Registry: reg, Domain: domain, Public: acme.TLSConfig(), IngressCert: ingCert, DataPlaneAddr: net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort))}
	go term.Serve(pubLn)
	defer term.Close()

	// --- a caller with its own identity ---
	callerKP, _ := identity.Generate(identity.AlgoEd25519)
	callerDER, _ := identity.SelfSignedCert(callerKP, "caller")
	callerCert := tls.Certificate{Certificate: [][]byte{callerDER}, PrivateKey: callerKP.Signer}

	// PASSTHROUGH: dial the ingress SNI port as alpha.example.test → alpha's own
	// cert is served, the caller's client cert is visible AT ALPHA
	get := func(addr, sni string, pool *x509.CertPool, pin string, path string, wait time.Duration) (string, error) {
		var last error
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			tc := &tls.Config{ServerName: sni, Certificates: []tls.Certificate{callerCert}, MinVersion: tls.VersionTLS12, RootCAs: pool}
			if pin != "" {
				tc.InsecureSkipVerify = true
				tc.VerifyConnection = func(cs tls.ConnectionState) error {
					f, _ := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
					if f != pin {
						return &pinErr{f}
					}
					return nil
				}
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				TLSClientConfig: tc,
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			}}
			resp, err := client.Get("https://" + sni + path)
			if err != nil {
				last = err
				time.Sleep(250 * time.Millisecond)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return strings.TrimSpace(string(b)), nil
		}
		return "", last
	}
	body, err := get(net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort)), "alpha."+domain, nil, alpha.kp.Fingerprint, "/whoami", 20*time.Second)
	if err != nil {
		t.Fatalf("passthrough: %v", err)
	}
	if !strings.Contains(body, `"node":"alpha"`) || !strings.Contains(body, `"peer":"`+callerKP.Fingerprint+`"`) {
		t.Fatalf("passthrough answer: %s", body)
	}
	// TERMINATE: dial the public port as beta.example.test → the ACME cert
	// validates against Pebble's roots, the ingress re-originates pinned mTLS
	// to beta, and beta answers — its onward leg saw the INGRESS (not the caller)
	body, err = get(pubLn.Addr().String(), "beta."+domain, trust, "", "/whoami", 20*time.Second)
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if !strings.Contains(body, `"node":"beta"`) || !strings.Contains(body, `"peer":"`+ingKP.Fingerprint+`"`) {
		t.Fatalf("terminate answer (edge: identity must come from the ingress leg, callers seal): %s", body)
	}
	// and a caller cannot reach beta's internal name through the SNI port with
	// its own cert: beta only accepts the pinned ingress
	if b, err := get(net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort)), ingress.InternalName("beta", domain), nil, beta.kp.Fingerprint, "/whoami", 3*time.Second); err == nil {
		t.Fatalf("beta's internal leg accepted a non-ingress client: %s", b)
	}
}

type pinErr struct{ got string }

func (e *pinErr) Error() string { return "served key " + e.got + " is not the pinned node" }
