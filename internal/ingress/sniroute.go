package ingress

// SNI passthrough router (SPEC §10.6 passthrough): the embedded frp server is
// the data plane — its vhost HTTPS port routes on SNI and forwards raw TLS to
// the node's reverse tunnel without terminating it. Registry integration
// rides frp's own server-plugin API: every Login and NewProxy is checked
// against the paired-node registry, so a tunnel can only claim the subdomain
// its pairing granted. Off-the-shelf on purpose.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/server"
)

// Login metadata keys a paired node sends (frp client Metadatas).
const (
	MetaNode   = "hdtp_node"   // node identity fingerprint
	MetaSecret = "hdtp_secret" // per-node secret from pairing
)

// DataPlane is the embedded frps plus the registry-enforcing plugin.
type DataPlane struct {
	Registry Registry
	Domain   string
	// BindAddr/BindPort: where nodes' frp clients connect (control plane).
	BindAddr string
	BindPort int
	// VhostHTTPSPort: the SNI-routed port the front door forwards passthrough
	// traffic to. It is an internal hop, not the public entrance.
	VhostHTTPSPort int
	// ProxyBindAddr is where the vhost listens; "" means loopback, which is
	// what an internal hop should be. The control port keeps BindAddr, because
	// nodes must be able to dial in from anywhere.
	ProxyBindAddr string
	// Token: shared frps transport token; per-node auth is the plugin's job.
	Token string
	Audit func(action, resource, outcome string)

	mu      sync.Mutex
	svc     *server.Service
	plugin  *http.Server
	pluginL net.Listener
	running bool
	// served is the plugin endpoint's Serve and frps' Run: Stop waits for both.
	served sync.WaitGroup
}

func (d *DataPlane) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// pluginHandler answers frps's server-plugin calls (Login, NewProxy).
// proxyBindAddr keeps the vhost off the public interfaces by default.
func (d *DataPlane) proxyBindAddr() string {
	if d.ProxyBindAddr != "" {
		return d.ProxyBindAddr
	}
	return "127.0.0.1"
}

func (d *DataPlane) pluginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req plugin.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, plugin.Response{Reject: true, RejectReason: "bad request"})
			return
		}
		raw, _ := json.Marshal(req.Content)
		switch req.Op {
		case "Login":
			var c plugin.LoginContent
			_ = json.Unmarshal(raw, &c)
			n, ok := d.Registry.ByFingerprint(c.Metas[MetaNode])
			if !ok || c.Metas[MetaSecret] == "" || c.Metas[MetaSecret] != n.Secret {
				d.audit("ingress_login", "node:"+c.Metas[MetaNode], "rejected")
				reply(w, plugin.Response{Reject: true, RejectReason: "unknown node or bad secret: pair first"})
				return
			}
			d.audit("ingress_login", "node:"+n.Fingerprint, "ok")
			reply(w, plugin.Response{Unchange: true})
		case "NewProxy":
			var c plugin.NewProxyContent
			_ = json.Unmarshal(raw, &c)
			n, ok := d.Registry.ByFingerprint(c.User.Metas[MetaNode])
			if !ok || c.User.Metas[MetaSecret] != n.Secret {
				reply(w, plugin.Response{Reject: true, RejectReason: "unpaired node"})
				return
			}
			// passthrough nodes serve the public name; terminate nodes serve
			// only their internal name (the ingress terminates the public one)
			want := n.Subdomain + "." + d.Domain
			if n.Mode == ModeTerminate {
				want = InternalName(n.Subdomain, d.Domain)
			}
			if c.ProxyType != "https" || len(c.CustomDomains) != 1 || !strings.EqualFold(c.CustomDomains[0], want) {
				d.audit("ingress_proxy", "node:"+n.Fingerprint, "rejected")
				reply(w, plugin.Response{Reject: true,
					RejectReason: fmt.Sprintf("this node may only serve https passthrough for %s", want)})
				return
			}
			d.audit("ingress_proxy", "subdomain:"+n.Subdomain, "ok")
			reply(w, plugin.Response{Unchange: true})
		default:
			reply(w, plugin.Response{Unchange: true})
		}
	})
}

func reply(w http.ResponseWriter, r plugin.Response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(r)
}

// Start brings up the plugin endpoint and the embedded frps.
func (d *DataPlane) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	d.pluginL = pl
	plugin := &http.Server{Handler: d.pluginHandler(), ReadHeaderTimeout: 10 * time.Second}
	d.plugin = plugin
	d.served.Go(func() { _ = plugin.Serve(pl) })

	cfg := &v1.ServerConfig{
		BindAddr: d.BindAddr, BindPort: d.BindPort, VhostHTTPSPort: d.VhostHTTPSPort,
		// frp defaults ProxyBindAddr to BindAddr, so the vhost would bind every
		// interface alongside the control port. Since the front door became the
		// public entrance, the vhost is an INTERNAL hop: reachable from outside
		// it lets a caller skip the registry lookup, the unpaired-name drop and
		// the passthrough/terminate decision entirely, including reaching a
		// terminate-mode node by its internal name.
		ProxyBindAddr: d.proxyBindAddr(),
		HTTPPlugins: []v1.HTTPPluginOptions{{
			Name: "hdtp-registry", Addr: pl.Addr().String(), Path: "/frp-plugin",
			Ops: []string{"Login", "NewProxy"},
		}},
	}
	if d.Token != "" {
		cfg.Auth.Method = v1.AuthMethodToken
		cfg.Auth.Token = d.Token
	}
	if err := cfg.Complete(); err != nil {
		_ = plugin.Close()
		d.served.Wait()
		d.plugin, d.pluginL = nil, nil
		return fmt.Errorf("ingress: frps config: %w", err)
	}
	svc, err := server.NewService(cfg)
	if err != nil {
		_ = plugin.Close()
		d.served.Wait()
		d.plugin, d.pluginL = nil, nil
		return fmt.Errorf("ingress: frps: %w", err)
	}
	d.served.Go(func() { svc.Run(ctx) })
	d.svc, d.running = svc, true
	return nil
}

func (d *DataPlane) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.svc != nil {
		_ = d.svc.Close()
	}
	if d.plugin != nil {
		_ = d.plugin.Close()
	}
	d.served.Wait()
	d.svc, d.plugin, d.pluginL, d.running = nil, nil, nil, false
	return nil
}
