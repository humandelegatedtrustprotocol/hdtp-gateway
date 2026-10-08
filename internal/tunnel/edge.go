package tunnel

// Edge-mode adapters (SPEC §10.1–§10.2): a third party terminates the public
// TLS session, so client certificates never reach the node and caller identity
// rests entirely on sealed envelopes. Both adapters here declare
// TerminatesAtEdge=true, which is what forces `seal: required` and
// `client_cert: off` at config resolution — the node never has to trust the
// adapter to say so.
//
// `cloudflare` runs the vendor's own connector (`cloudflared`) with a tunnel
// token, spawned as a supervised child when the binary is present, otherwise
// the owner runs the compose sidecar the node prints. `ngrok-https` uses the
// official ngrok agent's free HTTPS endpoint. Off-the-shelf on purpose.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	ngrok "golang.ngrok.com/ngrok/v2"
)

// TrustedClientIPHeader names the ONE header an edge adapter's own listener may
// take the source address from (SPEC §5.7). Generic X-Forwarded-For is never
// honored, anywhere. Only "cloudflare" has one ("CF-Connecting-IP"); every other adapter name
// returns "".
func TrustedClientIPHeader(adapter string) string {
	switch adapter {
	case "cloudflare":
		return "CF-Connecting-IP"
	default:
		return "" // no trusted header: per-IP limiting degrades to an aggregate cap
	}
}

// SourceIP resolves the client address for rate limiting. It honors the
// adapter's trusted header ONLY when that adapter terminates at an edge; on a
// direct listener the socket address is the only truth.
func SourceIP(adapter string, terminatesAtEdge bool, r *http.Request) string {
	if terminatesAtEdge {
		if h := TrustedClientIPHeader(adapter); h != "" {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				return v
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

/* ------------------------------ cloudflare ------------------------------ */

type cloudflareOpts struct {
	Token      string // tunnel token (from the keyring, never a config file)
	Hostname   string // the public hostname the tunnel routes to this node
	Binary     string // cloudflared path; "" = look it up on PATH
	SkipSpawn  bool   // true = the owner runs the compose sidecar
	PublicBind string
}

func cloudflareOptions(o Options) (cloudflareOpts, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	c := cloudflareOpts{Token: get("token"), Hostname: get("hostname"), Binary: get("binary"),
		SkipSpawn: get("sidecar") == "true", PublicBind: o.PublicBind}
	if c.Token == "" {
		c.Token = os.Getenv("TUNNEL_TOKEN")
	}
	if c.Token == "" {
		return c, fmt.Errorf("tunnel: cloudflare needs a tunnel token (portal → Settings → Tunnel; stored in the keyring)")
	}
	if c.Hostname == "" {
		return c, fmt.Errorf("tunnel: cloudflare needs the hostname the tunnel routes to this node")
	}
	return c, nil
}

// ComposeSidecar is the snippet the node prints when it cannot spawn the
// connector itself — the same service compose.yaml already carries. A non-empty token is never
// written into the snippet: it shows the reference ${TUNNEL_TOKEN}; an empty token shows a placeholder.
func ComposeSidecar(token string) string {
	shown := "${TUNNEL_TOKEN}"
	if token == "" {
		shown = "<your tunnel token>"
	}
	return "services:\n  cloudflared:\n    image: cloudflare/cloudflared:latest\n" +
		"    restart: unless-stopped\n    command: tunnel --no-autoupdate run\n" +
		"    environment:\n      TUNNEL_TOKEN: " + shown + "\n"
}

// Cloudflare is the edge adapter for the Cloudflare Tunnel connector (TerminatesAtEdge true).
// Its constructor refuses an empty tunnel token (the Extra key token, else $TUNNEL_TOKEN) and an
// empty hostname.
type Cloudflare struct {
	opts cloudflareOpts
	// spawn is the connector launcher (seam for tests).
	spawn func(ctx context.Context, bin, token string) (*exec.Cmd, error)

	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	detail  string
}

func spawnCloudflared(ctx context.Context, bin, token string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, bin, "tunnel", "--no-autoupdate", "run", "--token", token)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func init() {
	Register("cloudflare", true, func(o Options) (Adapter, error) {
		c, err := cloudflareOptions(o)
		if err != nil {
			return nil, err
		}
		return &Cloudflare{opts: c, spawn: spawnCloudflared}, nil
	})
	Register("ngrok-https", true, func(o Options) (Adapter, error) {
		n, err := ngrokHTTPSOptions(o)
		if err != nil {
			return nil, err
		}
		return &NgrokHTTPS{opts: n, listen: ngrokHTTPSListen}, nil
	})
}

// Start reports https://<hostname> with TerminatesAtEdge true. It spawns `cloudflared tunnel
// --no-autoupdate run --token …` as a child (binary from Extra "binary", else found on PATH) with
// only PATH and HOME in its environment. With Extra "sidecar" = "true", or when cloudflared is not
// found, it spawns nothing and succeeds with Running true and a Detail saying the owner runs the
// connector (the latter with the compose snippet); a failure to start the child is an error.
func (c *Cloudflare) Start(ctx context.Context) (Info, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := Info{PublicURL: "https://" + c.opts.Hostname, TerminatesAtEdge: true}
	if c.opts.SkipSpawn {
		c.running, c.detail = true, "connector runs as the compose sidecar; the node does not manage it"
		return info, nil
	}
	bin := c.opts.Binary
	if bin == "" {
		found, err := exec.LookPath("cloudflared")
		if err != nil {
			// Not an error: the owner runs the sidecar. The node says so plainly.
			c.running = true
			c.detail = "cloudflared not found on PATH — run the connector yourself:\n" + ComposeSidecar(c.opts.Token)
			return info, nil
		}
		bin = found
	}
	cmd, err := c.spawn(ctx, bin, c.opts.Token)
	if err != nil {
		return Info{}, fmt.Errorf("tunnel: cloudflared: %w", err)
	}
	c.cmd, c.running = cmd, true
	c.detail = "cloudflared child running; Cloudflare terminates TLS (edge mode: seal required, client certs never arrive)"
	return info, nil
}

// Status reports https://<hostname> and the Detail left by Start.
func (c *Cloudflare) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{Name: "cloudflare", Running: c.running, PublicURL: "https://" + c.opts.Hostname, Detail: c.detail}
}

// Stop kills the spawned connector, if any, and waits for it; the kill error is returned.
func (c *Cloudflare) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if c.cmd != nil && c.cmd.Process != nil {
		err = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
	c.cmd, c.running = nil, false
	return err
}

/* ------------------------------ ngrok-https ----------------------------- */

type ngrokHTTPSOpts struct {
	AuthToken string
	URL       string // https://… or "" for an allocated hostname
	Name      string
}

func ngrokHTTPSOptions(o Options) (ngrokHTTPSOpts, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	n := ngrokHTTPSOpts{AuthToken: get("auth_token"), URL: get("url"), Name: get("name")}
	if n.AuthToken == "" {
		n.AuthToken = os.Getenv("NGROK_AUTHTOKEN")
	}
	if n.AuthToken == "" {
		return n, fmt.Errorf("tunnel: ngrok-https needs auth_token (or NGROK_AUTHTOKEN) — the free plan is enough")
	}
	if n.URL == "" {
		n.URL = "https://"
	}
	if !strings.HasPrefix(n.URL, "https://") {
		return n, fmt.Errorf("tunnel: ngrok-https url must be https:// (use the `ngrok` adapter for tls:// passthrough)")
	}
	if n.Name == "" {
		n.Name = "hdtp"
	}
	return n, nil
}

// NgrokHTTPS is the free-plan edge adapter: ngrok terminates TLS (TerminatesAtEdge true). Its
// constructor refuses a missing auth token (Extra auth_token, else $NGROK_AUTHTOKEN) and a url
// that is not https://; the default url is "https://" (an allocated hostname).
type NgrokHTTPS struct {
	opts   ngrokHTTPSOpts
	listen func(ctx context.Context, o ngrokHTTPSOpts) (net.Listener, string, error)

	mu        sync.Mutex
	ln        net.Listener
	publicURL string
	running   bool
}

func ngrokHTTPSListen(ctx context.Context, o ngrokHTTPSOpts) (net.Listener, string, error) {
	agent, err := ngrok.NewAgent(ngrok.WithAuthtoken(o.AuthToken))
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: ngrok agent: %w", err)
	}
	ln, err := agent.Listen(ctx, ngrok.WithURL(o.URL), ngrok.WithName(o.Name))
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: ngrok-https listen: %w", err)
	}
	return ln, ln.URL().String(), nil
}

// Start opens the ngrok HTTPS endpoint and returns its URL with TerminatesAtEdge true and the
// Listener, which carries decrypted HTTP: the node serves plain HTTP on it.
func (a *NgrokHTTPS) Start(ctx context.Context) (Info, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ln, endpoint, err := a.listen(ctx, a.opts)
	if err != nil {
		return Info{}, err
	}
	a.ln, a.publicURL, a.running = ln, endpoint, true
	// The stream ngrok hands back carries DECRYPTED HTTP: the node serves plain
	// HTTP on it and identity comes from sealed envelopes only (edge mode).
	return Info{PublicURL: endpoint, TerminatesAtEdge: true, Listener: ln}, nil
}

// Status reports the endpoint URL and that ngrok terminates TLS.
func (a *NgrokHTTPS) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{Name: "ngrok-https", Running: a.running, PublicURL: a.publicURL,
		Detail: "ngrok terminates TLS (edge mode: seal required, client certs never arrive)"}
}

// Stop closes the ngrok listener and returns its close error.
func (a *NgrokHTTPS) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	if a.ln != nil {
		err = a.ln.Close()
	}
	a.ln, a.running = nil, false
	return err
}
