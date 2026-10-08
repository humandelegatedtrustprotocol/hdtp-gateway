package tunnel

// tailscale adapter (SPEC §10.2): a thin wrap of the official tsnet library.
// Funnel hands the node a raw TCP stream from the public internet; the node
// runs its OWN TLS on it, so client certificates stay visible end to end and
// the Funnel relay never decrypts — direct mode, TerminatesAtEdge=false.
// Off-the-shelf on purpose: everything network-shaped is tsnet's.
//
// Limits (verified 2026-08-24 against tsnet docs): TCP only; ports 443, 8443,
// 10000; the hostname is the tsnet node's *.ts.net name; Funnel is beta and
// Tailscale-hosted; Funnel must be enabled for the tailnet in the admin console.

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"tailscale.com/tsnet"
)

type tailscaleOpts struct {
	Hostname   string
	AuthKey    string
	StateDir   string
	Port       int
	FunnelOnly bool
	ControlURL string
}

// funnelPorts are the only ports Funnel serves (tsnet documentation).
var funnelPorts = map[int]bool{443: true, 8443: true, 10000: true}

// tailscaleOptions validates the adapter's configuration (pure; unit-tested).
// Extra keys: hostname (required), auth_key (or TS_AUTHKEY env), state_dir,
// port (443|8443|10000, default 443), funnel_only (true|false), control_url.
func tailscaleOptions(o Options) (tailscaleOpts, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	t := tailscaleOpts{
		Hostname: get("hostname"), AuthKey: get("auth_key"), StateDir: get("state_dir"),
		Port: 443, FunnelOnly: get("funnel_only") == "true", ControlURL: get("control_url"),
	}
	if t.Hostname == "" {
		return t, fmt.Errorf("tunnel: tailscale needs hostname (the tsnet node name, becomes <hostname>.<tailnet>.ts.net)")
	}
	if t.AuthKey == "" {
		t.AuthKey = os.Getenv("TS_AUTHKEY")
	}
	if t.AuthKey == "" {
		return t, fmt.Errorf("tunnel: tailscale needs auth_key (or TS_AUTHKEY) — a reusable, preauthorized key from the admin console")
	}
	if p := get("port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return t, fmt.Errorf("tunnel: tailscale port %q is not a number", p)
		}
		t.Port = n
	}
	if !funnelPorts[t.Port] {
		return t, fmt.Errorf("tunnel: Funnel serves only ports 443, 8443 and 10000 (got %d)", t.Port)
	}
	return t, nil
}

// funnelURL is the public base a Funnel listener is reachable at.
func funnelURL(domain string, port int) string {
	if port == 443 {
		return "https://" + domain
	}
	return "https://" + domain + ":" + strconv.Itoa(port)
}

// Tailscale is the Funnel adapter (TerminatesAtEdge false); the tsnet.Server owns all networking.
// Its constructor refuses a missing hostname, a missing auth key (Extra auth_key, else $TS_AUTHKEY)
// and a port other than 443, 8443 or 10000 (default 443).
type Tailscale struct {
	opts tailscaleOpts

	mu        sync.Mutex
	srv       *tsnet.Server
	ln        net.Listener
	publicURL string
	running   bool
	detail    string
}

func init() {
	Register("tailscale", false, func(o Options) (Adapter, error) {
		t, err := tailscaleOptions(o)
		if err != nil {
			return nil, err
		}
		return &Tailscale{opts: t}, nil
	})
}

// Start brings the tsnet node up, requires it to have a *.ts.net name, and listens with Funnel on the
// configured port. It returns https://<that name>[:port] with TerminatesAtEdge false and the raw
// Listener, on which the node runs its own TLS. Every failure closes the tsnet server again.
func (t *Tailscale) Start(ctx context.Context) (Info, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	srv := &tsnet.Server{
		Hostname:   t.opts.Hostname,
		AuthKey:    t.opts.AuthKey,
		Dir:        t.opts.StateDir,
		ControlURL: t.opts.ControlURL,
		Logf:       func(string, ...any) {}, // tsnet is chatty; the node has its own audit/log
	}
	if _, err := srv.Up(ctx); err != nil {
		_ = srv.Close()
		return Info{}, fmt.Errorf("tunnel: tailscale up: %w", err)
	}
	domains := srv.CertDomains()
	if len(domains) == 0 {
		_ = srv.Close()
		return Info{}, fmt.Errorf("tunnel: tailscale node has no *.ts.net name yet (enable MagicDNS + HTTPS certificates for the tailnet)")
	}
	var fopts []tsnet.FunnelOption
	if t.opts.FunnelOnly {
		fopts = append(fopts, tsnet.FunnelOnly())
	}
	ln, err := srv.ListenFunnel("tcp", ":"+strconv.Itoa(t.opts.Port), fopts...)
	if err != nil {
		_ = srv.Close()
		return Info{}, fmt.Errorf("tunnel: tailscale funnel: %w (is Funnel enabled for this tailnet?)", err)
	}
	t.srv, t.ln, t.running = srv, ln, true
	t.publicURL = funnelURL(domains[0], t.opts.Port)
	t.detail = "Funnel on " + domains[0] + " (beta, Tailscale-hosted; the relay does not decrypt)"
	return Info{PublicURL: t.publicURL, TerminatesAtEdge: false, Listener: ln}, nil
}

// Status reports the Funnel URL and the Detail left by Start.
func (t *Tailscale) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Status{Name: "tailscale", Running: t.running, PublicURL: t.publicURL, Detail: t.detail}
}

// Stop closes the Funnel listener and the tsnet server; the first close error is returned.
func (t *Tailscale) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	if t.ln != nil {
		err = t.ln.Close()
	}
	if t.srv != nil {
		if cerr := t.srv.Close(); err == nil {
			err = cerr
		}
	}
	t.running, t.ln, t.srv = false, nil, nil
	return err
}
