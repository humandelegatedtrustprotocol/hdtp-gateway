package tunnel

// frp adapter (SPEC §10.2): the official frp client library embedded, talking
// to an owner-run frps on any VPS. frps forwards raw bytes — SNI-routed
// (`https` proxy type) or by dedicated remote port (`tcp`) — and never
// terminates TLS, so the node's own mTLS survives end to end: direct mode,
// TerminatesAtEdge=false. Incoming connections are delivered by the frp client
// dialing the node's local public bind, so no Listener is handed back.
// Off-the-shelf on purpose: everything network-shaped is frp's. The build takes
// frp from third_party/frp, upstream v0.71.0 with two data races in its client
// fixed (third_party/frp.patch; scripts/frp-patch.sh says why and holds the copy
// to exactly that).

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type frpOpts struct {
	ServerAddr   string
	ServerPort   int
	Token        string
	ProxyType    string // tcp | https
	Name         string
	RemotePort   int    // tcp
	CustomDomain string // https (SNI routed by frps' vhostHTTPSPort)
	VhostPort    int    // https: frps vhostHTTPSPort, for the public URL (default 443)
	LocalIP      string
	LocalPort    int
	// Metadatas ride the frp login (Extra keys prefixed meta_): the ingress
	// role's server plugin authenticates a paired node from them (SPEC §10.6).
	Metadatas map[string]string
}

// frpOptions validates the adapter configuration (pure; unit-tested). Extra
// keys: server_addr (required), server_port (default 7000), token, proxy_type
// (tcp default | https), remote_port (tcp, required), custom_domain (https,
// required), vhost_https_port (https, default 443), name (default "hdtp").
func frpOptions(o Options) (frpOpts, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	f := frpOpts{
		ServerAddr: get("server_addr"), ServerPort: 7000, Token: get("token"),
		ProxyType: get("proxy_type"), Name: get("name"), CustomDomain: get("custom_domain"), VhostPort: 443,
	}
	if f.ServerAddr == "" {
		return f, fmt.Errorf("tunnel: frp needs server_addr (your frps host)")
	}
	if f.ProxyType == "" {
		f.ProxyType = "tcp"
	}
	if f.Name == "" {
		f.Name = "hdtp"
	}
	num := func(key string, dst *int) error {
		if v := get(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 65535 {
				return fmt.Errorf("tunnel: frp %s %q is not a port", key, v)
			}
			*dst = n
		}
		return nil
	}
	for key, dst := range map[string]*int{"server_port": &f.ServerPort, "remote_port": &f.RemotePort, "vhost_https_port": &f.VhostPort} {
		if err := num(key, dst); err != nil {
			return f, err
		}
	}
	switch f.ProxyType {
	case "tcp":
		if f.RemotePort == 0 {
			return f, fmt.Errorf("tunnel: frp tcp proxy needs remote_port (the public port frps opens)")
		}
	case "https":
		if f.CustomDomain == "" {
			return f, fmt.Errorf("tunnel: frp https proxy needs custom_domain (SNI frps routes on)")
		}
	default:
		return f, fmt.Errorf("tunnel: frp proxy_type %q (want tcp|https)", f.ProxyType)
	}
	for k, v := range o.Extra {
		if strings.HasPrefix(k, "meta_") {
			if f.Metadatas == nil {
				f.Metadatas = map[string]string{}
			}
			f.Metadatas[strings.TrimPrefix(k, "meta_")] = v
		}
	}
	host, port, err := net.SplitHostPort(o.PublicBind)
	if err != nil {
		return f, fmt.Errorf("tunnel: frp needs the node's public_bind as host:port: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	f.LocalIP = host
	if f.LocalPort, err = strconv.Atoi(port); err != nil {
		return f, fmt.Errorf("tunnel: public_bind port: %w", err)
	}
	return f, nil
}

func (f frpOpts) publicURL() string {
	if f.ProxyType == "https" {
		if f.VhostPort == 443 {
			return "https://" + f.CustomDomain
		}
		return "https://" + f.CustomDomain + ":" + strconv.Itoa(f.VhostPort)
	}
	return "https://" + net.JoinHostPort(f.ServerAddr, strconv.Itoa(f.RemotePort))
}

// proxyConfig builds the frp proxy the client registers.
func (f frpOpts) proxyConfig() (v1.ProxyConfigurer, error) {
	base := v1.ProxyBaseConfig{Name: f.Name, Type: f.ProxyType}
	base.LocalIP = f.LocalIP
	base.LocalPort = f.LocalPort
	var cfg v1.ProxyConfigurer
	switch f.ProxyType {
	case "tcp":
		cfg = &v1.TCPProxyConfig{ProxyBaseConfig: base, RemotePort: f.RemotePort}
	case "https":
		cfg = &v1.HTTPSProxyConfig{ProxyBaseConfig: base, DomainConfig: v1.DomainConfig{CustomDomains: []string{f.CustomDomain}}}
	default:
		return nil, fmt.Errorf("tunnel: frp proxy_type %q", f.ProxyType)
	}
	cfg.Complete()
	return cfg, nil
}

// FRP is the adapter; the frp client Service owns all networking.
type FRP struct {
	opts frpOpts

	mu      sync.Mutex
	svc     *client.Service
	cancel  context.CancelFunc
	runDone chan struct{}
	running bool
}

func init() {
	Register("frp", false, func(o Options) (Adapter, error) {
		f, err := frpOptions(o)
		if err != nil {
			return nil, err
		}
		return &FRP{opts: f}, nil
	})
}

func (a *FRP) Start(ctx context.Context) (Info, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	common := &v1.ClientCommonConfig{ServerAddr: a.opts.ServerAddr, ServerPort: a.opts.ServerPort, Metadatas: a.opts.Metadatas}
	if a.opts.Token != "" {
		common.Auth.Method = v1.AuthMethodToken
		common.Auth.Token = a.opts.Token
	}
	if err := common.Complete(); err != nil {
		return Info{}, fmt.Errorf("tunnel: frp config: %w", err)
	}
	pcfg, err := a.opts.proxyConfig()
	if err != nil {
		return Info{}, err
	}
	// in-memory config source, the same plumbing frpc itself uses
	cs := source.NewConfigSource()
	if err := cs.ReplaceAll([]v1.ProxyConfigurer{pcfg}, nil); err != nil {
		return Info{}, fmt.Errorf("tunnel: frp proxy: %w", err)
	}
	svc, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(cs)})
	if err != nil {
		return Info{}, fmt.Errorf("tunnel: frp client: %w", err)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() { defer close(done); _ = svc.Run(runCtx) }()
	a.svc, a.cancel, a.runDone, a.running = svc, cancel, done, true
	return Info{PublicURL: a.opts.publicURL(), TerminatesAtEdge: false}, nil
}

func (a *FRP) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{Name: "frp", Running: a.running, PublicURL: a.opts.publicURL(),
		Detail: fmt.Sprintf("%s proxy %q via frps %s:%d (raw passthrough; frps does not terminate TLS)",
			a.opts.ProxyType, a.opts.Name, a.opts.ServerAddr, a.opts.ServerPort)}
}

// Stop shuts frp down the way frpc does — GracefulClose, then wait for Run to
// return — and only THEN releases the context; cancelling first races frp's
// own keepalive goroutine against its stop path.
func (a *FRP) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.svc != nil {
		a.svc.GracefulClose(2 * time.Second)
	}
	if a.runDone != nil {
		select {
		case <-a.runDone:
		case <-time.After(5 * time.Second):
		}
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.svc, a.cancel, a.runDone, a.running = nil, nil, nil, false
	return nil
}
