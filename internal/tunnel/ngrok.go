package tunnel

// ngrok adapter (SPEC §10.2): the official ngrok-go v2 agent asks for a TLS
// endpoint (`tls://…`) and returns the UNTERMINATED stream, on which the node
// runs its own TLS — client certificates stay visible: direct mode,
// TerminatesAtEdge=false. TLS endpoints are a PAID ngrok feature, so the
// adapter is config-gated: without an authtoken it refuses to construct.
// Off-the-shelf on purpose: everything network-shaped is ngrok's.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	ngrok "golang.ngrok.com/ngrok/v2"
)

type ngrokOpts struct {
	AuthToken string
	URL       string // tls://<domain> (reserved domain) or "tls://" for an allocated one
	Name      string
}

// ngrokOptions validates configuration (pure; unit-tested). Extra keys:
// auth_token (or NGROK_AUTHTOKEN env; required — paid TLS endpoints), url
// (default "tls://"), name.
func ngrokOptions(o Options) (ngrokOpts, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	n := ngrokOpts{AuthToken: get("auth_token"), URL: get("url"), Name: get("name")}
	if n.AuthToken == "" {
		n.AuthToken = os.Getenv("NGROK_AUTHTOKEN")
	}
	if n.AuthToken == "" {
		return n, fmt.Errorf("tunnel: ngrok is disabled: TLS endpoints need a paid ngrok account — set auth_token (or NGROK_AUTHTOKEN)")
	}
	if n.URL == "" {
		n.URL = "tls://"
	}
	if !strings.HasPrefix(n.URL, "tls://") {
		return n, fmt.Errorf("tunnel: ngrok url must be a tls:// endpoint (raw passthrough); got %q", n.URL)
	}
	if n.Name == "" {
		n.Name = "hdtp"
	}
	return n, nil
}

// publicURLFromTLS turns the endpoint's tls://host[:port] into the https base
// the card advertises.
func publicURLFromTLS(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("tunnel: ngrok endpoint %q has no host", endpoint)
	}
	if u.Port() == "443" {
		return "https://" + u.Hostname(), nil
	}
	return "https://" + u.Host, nil
}

// listenFunc opens the raw TLS endpoint; the real one calls ngrok, tests
// inject a local net.Listener.
type listenFunc func(ctx context.Context, o ngrokOpts) (net.Listener, string, error)

func ngrokListen(ctx context.Context, o ngrokOpts) (net.Listener, string, error) {
	agent, err := ngrok.NewAgent(ngrok.WithAuthtoken(o.AuthToken))
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: ngrok agent: %w", err)
	}
	ln, err := agent.Listen(ctx, ngrok.WithURL(o.URL), ngrok.WithName(o.Name))
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: ngrok listen %s: %w (TLS endpoints are not on the free plan)", o.URL, err)
	}
	return ln, ln.URL().String(), nil
}

// Ngrok is the paid-plan adapter (TerminatesAtEdge false); the ngrok agent owns all networking. Its
// constructor refuses a missing auth token (Extra auth_token, else $NGROK_AUTHTOKEN) and a url that
// is not a tls:// endpoint; the default url is "tls://".
type Ngrok struct {
	opts   ngrokOpts
	listen listenFunc

	mu        sync.Mutex
	ln        net.Listener
	publicURL string
	running   bool
}

func init() {
	Register("ngrok", false, func(o Options) (Adapter, error) {
		n, err := ngrokOptions(o)
		if err != nil {
			return nil, err
		}
		return &Ngrok{opts: n, listen: ngrokListen}, nil
	})
}

// Start opens the ngrok tls:// endpoint and returns the https base for it (the port is omitted when
// it is 443) with TerminatesAtEdge false and the raw Listener, on which the node runs its own TLS.
func (a *Ngrok) Start(ctx context.Context) (Info, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ln, endpoint, err := a.listen(ctx, a.opts)
	if err != nil {
		return Info{}, err
	}
	pub, err := publicURLFromTLS(endpoint)
	if err != nil {
		_ = ln.Close()
		return Info{}, err
	}
	a.ln, a.publicURL, a.running = ln, pub, true
	// the raw stream: the node runs its OWN TLS on it (client certs visible)
	return Info{PublicURL: pub, TerminatesAtEdge: false, Listener: ln}, nil
}

// Status reports the advertised URL and that the endpoint is passthrough.
func (a *Ngrok) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{Name: "ngrok", Running: a.running, PublicURL: a.publicURL,
		Detail: "tls:// endpoint (paid); ngrok forwards the raw stream without terminating TLS"}
}

// Stop closes the ngrok listener and returns its close error.
func (a *Ngrok) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	if a.ln != nil {
		err = a.ln.Close()
	}
	a.ln, a.running = nil, false
	return err
}
