package cli

// The ingress role (SPEC §2.2, §10.6): the owner's own front door. It is the
// same binary in a different role — no store, no accounts, no MCP surface of
// its own. It holds a registry of paired nodes, a pairing endpoint that hands
// out one-time tokens, an frp data plane the nodes dial out to, and (for
// `terminate` subdomains) an ACME certificate and a mutually-pinned onward leg.
//
// Passthrough subdomains never see plaintext: SNI routes the whole TLS session
// to the node, whose own certificate the caller pins (SPEC §3.8).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/ingress"
	"github.com/pact-cloud/pact-gateway/internal/ingress/dns"
)

type ingressFlags struct {
	dataDir           string
	dns               string
	cfToken           string
	domain            string
	pairBind          string
	dataPlaneAddr     string
	dataPlanePort     int
	vhostPort         int
	token             string
	keyFile           string
	acmeEmail         string
	acmeDir           string
	acmeCA            string
	acmeCARoot        string
	terminate         bool
	internalVhostPort int
}

// ingressCmd dispatches the ingress role's subcommands.
func ingressCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway ingress <serve|token> [flags]")
		return 2
	}
	switch args[0] {
	case "serve":
		return ingressServe(args[1:], stdout, stderr)
	case "token":
		return ingressToken(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "ingress: unknown subcommand %q (want serve|token)\n", args[0])
		return 2
	}
}

// ingressToken mints a single-use pairing token from a RUNNING ingress, over
// its admin socket — the registry lives in that process, so there is nothing to
// mint from on the outside.
func ingressToken(args []string, stdout, stderr io.Writer) int {
	var dataDir string
	fs := flag.NewFlagSet("ingress token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&dataDir, "data-dir", ingressDataDir(), "the running ingress's data directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := core.AdminCall(core.AdminSocketPath(dataDir), "ingress.token", nil, &out); err != nil {
		fmt.Fprintln(stderr, "ingress token:", err)
		return 1
	}
	fmt.Fprintln(stdout, out.Token)
	return 0
}

// ingressDataDir is where the ingress keeps its admin socket and identity key.
func ingressDataDir() string {
	if v := os.Getenv("PACT_DATA_DIR"); v != "" {
		return v
	}
	return "./data"
}

// ingressFlagSet is the ingress role's command line, split from ingressServe so
// a test can drive argv all the way into the options it produces. A flag that is
// registered and then never read looks identical from `-h`.
func ingressFlagSet(f *ingressFlags, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("ingress serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.dataDir, "data-dir", ingressDataDir(), "identity key and admin socket live here")
	fs.StringVar(&f.dns, "dns", "", "DNS adapter for records and DNS-01 (cloudflare)")
	fs.StringVar(&f.cfToken, "cloudflare-token", "", "Cloudflare API token (Zone.DNS:Write); default $CF_TOKEN")
	fs.StringVar(&f.domain, "domain", "", "the domain whose subdomains front paired nodes (required)")
	fs.StringVar(&f.pairBind, "pair-bind", "127.0.0.1:8444", "pairing endpoint bind")
	fs.StringVar(&f.dataPlaneAddr, "data-plane-addr", "", "address nodes dial for the data plane (default: the domain)")
	fs.IntVar(&f.dataPlanePort, "data-plane-port", 7000, "data-plane control port nodes dial")
	fs.IntVar(&f.vhostPort, "vhost-port", 443, "public port serving both modes by SNI")
	fs.StringVar(&f.token, "token", "", "shared data-plane transport token (default: PACT_INGRESS_TOKEN)")
	fs.StringVar(&f.keyFile, "key", "", "ingress identity key file (default: <domain>.key in the working directory)")
	fs.StringVar(&f.acmeEmail, "acme-email", "", "contact address for ACME registration; enables terminate mode")
	fs.StringVar(&f.acmeDir, "acme-dir", "", "ACME storage directory (default: ./acme)")
	fs.BoolVar(&f.terminate, "terminate", false, "also terminate TLS for terminate-mode subdomains on the public port")
	fs.IntVar(&f.internalVhostPort, "internal-vhost-port", 7443, "loopback port the data plane routes passthrough SNI on")
	fs.StringVar(&f.acmeCA, "acme-ca", "", "ACME directory URL (default: Let's Encrypt production). "+
		"Rehearse with https://acme-staging-v02.api.letsencrypt.org/directory — production rate-limits "+
		"FAILED validations, which is what a first ingress produces")
	fs.StringVar(&f.acmeCARoot, "acme-ca-root", "", "PEM roots to trust for the ACME CA's OWN https "+
		"(private CAs such as step-ca); does not affect peer or contact verification")
	return fs
}

// acmeOptions turns the parsed flags into the issuer configuration.
func acmeOptions(f ingressFlags) (ingress.ACMEOptions, error) {
	if f.acmeDir == "" {
		f.acmeDir = "acme"
	}
	o := ingress.ACMEOptions{StorageDir: f.acmeDir, Email: f.acmeEmail, CA: f.acmeCA, HTTP01Port: 80}
	if f.acmeCARoot == "" {
		return o, nil
	}
	// An unreadable root must STOP startup. Falling back to the system pool would
	// send the ingress to the public CA while the owner believes it is aimed at
	// their private one — and they would only find out from the issued chain.
	b, err := os.ReadFile(f.acmeCARoot)
	if err != nil {
		return o, fmt.Errorf("acme ca root: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return o, fmt.Errorf("acme ca root %s: no PEM certificates found", f.acmeCARoot)
	}
	o.TrustedRoots = pool
	return o, nil
}

func ingressServe(args []string, stdout, stderr io.Writer) int {
	var f ingressFlags
	fs := ingressFlagSet(&f, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if f.domain == "" {
		fmt.Fprintln(stderr, "ingress: -domain is required")
		return 2
	}
	if f.token == "" {
		f.token = os.Getenv("PACT_INGRESS_TOKEN")
	}
	if f.token == "" {
		fmt.Fprintln(stderr, "ingress: a data-plane token is required (-token or PACT_INGRESS_TOKEN)")
		return 2
	}
	if f.dataPlaneAddr == "" {
		f.dataPlaneAddr = f.domain
	}
	if f.keyFile == "" {
		f.keyFile = filepath.Join(f.dataDir, "ingress.key")
	}
	if f.cfToken == "" {
		f.cfToken = os.Getenv("CF_TOKEN")
	}

	kp, err := loadOrCreateKey(f.keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "ingress:", err)
		return 1
	}
	der, err := identity.SelfSignedCert(kp, f.domain)
	if err != nil {
		fmt.Fprintln(stderr, "ingress:", err)
		return 1
	}
	ingCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}

	// manageName obtains a certificate for one subdomain. It is a no-op unless
	// terminate mode is on, or when a wildcard already covers every name.
	manageName := func(string) {}
	// terminateCh receives connections the front door routes to terminate mode;
	// nil while terminate mode is off, and then every subdomain is passthrough.
	var terminateCh ingress.ConnSink
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Pairings must survive a restart: an in-memory book meant every paired
	// node became unknown after a deploy and had to be re-paired by hand.
	reg, err := ingress.NewFileRegistry(filepath.Join(f.dataDir, "ingress-nodes.json"), nil)
	if err != nil {
		fmt.Fprintln(stderr, "ingress:", err)
		return 1
	}
	auditFn := func(action, resource, outcome string) {
		fmt.Fprintf(stdout, "%s %s %s\n", action, resource, outcome)
	}

	dp := &ingress.DataPlane{
		Registry: reg, Domain: f.domain, BindAddr: "0.0.0.0",
		BindPort: f.dataPlanePort, VhostHTTPSPort: f.internalVhostPort, Token: f.token, Audit: auditFn,
	}
	if err := dp.Start(ctx); err != nil {
		fmt.Fprintln(stderr, "ingress: data plane:", err)
		return 1
	}
	defer func() { _ = dp.Stop() }()

	// terminate mode is opt-in: without an ACME contact there is no certificate
	// to terminate with, and passthrough alone is a complete, useful ingress.
	if f.terminate {
		opts, oerr := acmeOptions(f)
		if oerr != nil {
			fmt.Fprintln(stderr, "ingress:", oerr)
			return 2
		}
		f.acmeDir = opts.StorageDir
		if f.dns == "cloudflare" {
			cf, err := dns.NewCloudflare(f.cfToken, f.domain)
			if err != nil {
				fmt.Fprintln(stderr, "ingress: cloudflare dns:", err)
				return 1
			}
			// DNS-01 is what makes a wildcard possible and removes the need for
			// port 80 to be reachable (SPEC §10.6).
			opts.DNS = cf.Solver()
		}
		acme, err := ingress.NewACME(opts)
		if err != nil {
			fmt.Fprintln(stderr, "ingress: acme:", err)
			return 1
		}
		defer acme.Close()
		term := &ingress.Terminator{
			Registry: reg, Domain: f.domain, Public: acme.TLSConfig(), IngressCert: ingCert,
			// The INTERNAL vhost, not the public port. P10-06d moved the frps
			// vhost to internalVhostPort and handed vhostPort to the front door;
			// this dial was left behind, so the terminator opened a connection
			// back to the FRONT DOOR carrying SNI `<sub>.internal.<domain>`,
			// whose stripped label contains a dot and can therefore never be a
			// registry key — every terminate request was dropped as unpaired.
			DataPlaneAddr: fmt.Sprintf("127.0.0.1:%d", f.internalVhostPort), Audit: auditFn,
		}
		// The terminator no longer owns a port. It consumes whatever the front
		// door decides is terminate traffic, so both modes share the public one
		// and a terminate-mode node is reachable at plain `https://name.domain`.
		termLn := ingress.NewChanListener(&net.TCPAddr{IP: net.IPv4zero, Port: f.vhostPort})
		terminateCh = termLn
		go func() { _ = term.Serve(termLn) }()
		defer func() { _ = term.Close(); _ = termLn.Close() }()
		fmt.Fprintf(stdout, "terminate: shares :%d by SNI (ACME storage %s)\n", f.vhostPort, f.acmeDir)

		// Nothing ever told certmagic WHICH names to obtain, so its
		// GetCertificate had nothing to answer with and every terminate
		// handshake failed — unlogged, because the failure is inside the TLS
		// handshake and never reaches a handler (SPEC §10.6).
		manageName = func(sub string) {
			name := sub + "." + f.domain
			mctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := acme.Manage(mctx, name); err != nil {
				auditFn("acme_manage", "name:"+name, "error")
				fmt.Fprintf(stderr, "ingress: could not obtain a certificate for %s: %v\n", name, err)
				return
			}
			auditFn("acme_manage", "name:"+name, "ok")
		}
		if f.cfToken != "" {
			// With DNS-01 a single wildcard covers every subdomain, so no
			// per-name issuance is needed and no per-pairing DNS record either:
			// the owner points *.<domain> at this host once.
			wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			if err := acme.Manage(wctx, "*."+f.domain); err != nil {
				fmt.Fprintf(stderr, "ingress: could not obtain a wildcard for *.%s: %v\n", f.domain, err)
				auditFn("acme_manage", "name:*."+f.domain, "error")
			} else {
				auditFn("acme_manage", "name:*."+f.domain, "ok")
				manageName = func(string) {} // the wildcard already covers it
				fmt.Fprintf(stdout, "certificate: wildcard *.%s — point its DNS at this host\n", f.domain)
			}
			cancel()
		} else {
			fmt.Fprintf(stdout, "certificate: per-subdomain over HTTP-01 — each <sub>.%s "+
				"must resolve to this host and port 80 must be reachable\n", f.domain)
		}
		// Names paired BEFORE this start still need certificates.
		for _, n := range reg.All() {
			if n.Mode == ingress.ModeTerminate {
				manageName(n.Subdomain)
			}
		}
	}

	// One public port for both modes (SPEC §10.6). Passthrough is spliced to the
	// data plane untouched — the ingress must not be able to read it — and
	// terminate traffic goes to the terminator with its ClientHello intact.
	front, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", f.vhostPort))
	if err != nil {
		fmt.Fprintln(stderr, "ingress: public listener:", err)
		return 1
	}
	fd := &ingress.FrontDoor{
		Registry: reg, Domain: f.domain, Terminate: terminateCh,
		PassthroughAddr: fmt.Sprintf("127.0.0.1:%d", f.internalVhostPort), Audit: auditFn,
	}
	go func() { _ = fd.Serve(front) }()
	defer func() { _ = fd.Close() }()
	fmt.Fprintf(stdout, "public:   :%d (SNI-routed)\n", f.vhostPort)

	// `ingress token` mints through this socket: the registry lives here.
	admin := core.NewAdminServer(core.AdminSocketPath(f.dataDir))
	admin.Handle("ingress.token", func(map[string]string) (any, error) {
		tok, err := reg.MintToken(10 * time.Minute)
		if err != nil {
			return nil, err
		}
		return map[string]string{"token": tok}, nil
	})
	if err := admin.Start(ctx); err != nil {
		fmt.Fprintln(stderr, "ingress: admin socket:", err)
		return 1
	}
	defer admin.Close()

	ps := &ingress.PairingServer{
		Registry: reg, Domain: f.domain, IngressFingerprint: kp.Fingerprint,
		DataPlaneAddr: f.dataPlaneAddr, DataPlanePort: f.dataPlanePort,
		DataPlaneToken: f.token, Audit: auditFn,
		// A terminate pairing is not usable until its name has a certificate.
		OnPaired: func(n ingress.Node) {
			if n.Mode == ingress.ModeTerminate {
				manageName(n.Subdomain)
			}
		},
	}
	srv := &http.Server{
		Addr: f.pairBind, Handler: ps.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(stdout, "pact-gateway ingress: domain=%s fingerprint=%s\n", f.domain, kp.Fingerprint)
	fmt.Fprintf(stdout, "pairing:  https://%s/pair\n", f.pairBind)
	fmt.Fprintf(stdout, "data plane: %s:%d (nodes dial this; passthrough SNI is routed on loopback :%d)\n",
		f.dataPlaneAddr, f.dataPlanePort, f.internalVhostPort)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return 0
	case err := <-errc:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(stderr, "ingress:", err)
			return 1
		}
		return 0
	}
}

// loadOrCreateKey keeps the ingress identity stable across restarts: paired
// nodes pin this key, so a fresh one on every start would break every pairing.
func loadOrCreateKey(path string) (*identity.Keypair, error) {
	if der, err := os.ReadFile(path); err == nil {
		return identity.ParsePKCS8(der)
	}
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		return nil, err
	}
	der, err := identity.MarshalPKCS8(kp)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, der, 0o600); err != nil {
		return nil, fmt.Errorf("ingress: storing the identity key: %w", err)
	}
	return kp, nil
}
