// Package tunnel implements tunnel adapters and reachability (SPEC §10).
//
// An adapter affects reachability ONLY: the protocol surface never changes
// because of a tunnel. Each adapter declares one boolean, TerminatesAtEdge,
// and config resolution derives the deployment mode (direct vs edge) and the
// forced knobs from it (SPEC §10.1). Adapters register their name and that
// boolean with core at init so resolution never needs to instantiate one.
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// Info is what Start reports back (SPEC §10: Start → {PublicURL, TerminatesAtEdge}).
type Info struct {
	// PublicURL is the externally reachable base URL peers are given.
	PublicURL string
	// TerminatesAtEdge is the adapter's one boolean: true when a third party terminates the
	// public TLS session (edge mode), false when the caller's TLS reaches the node (direct mode).
	TerminatesAtEdge bool
	// Listener, when non-nil, is the raw stream the adapter delivers callers on
	// (tailscale, ngrok, ngrok-https; frp and direct return none): the node runs its OWN TLS on it, so client
	// certificates stay visible end to end (SPEC §10.2). Direct leaves it nil —
	// the node's own bind is the public endpoint.
	Listener net.Listener
}

// Status is the adapter's live state for the portal/doctor.
type Status struct {
	// Name is the adapter name as registered, except that the two ingress adapters report "frp",
	// the adapter they wrap.
	Name string `json:"name"`
	// Running is true between a successful Start and Stop. For cloudflare it is also true when the
	// connector was not started by the node (sidecar, or cloudflared not found); Detail says which.
	Running bool `json:"running"`
	// PublicURL is the base URL the adapter advertises; empty until an allocating adapter has started.
	PublicURL string `json:"public_url,omitempty"`
	// Detail is the line the portal and doctor show; some adapters put a command to run in it (cloudflare without a connector).
	Detail string `json:"detail,omitempty"`
}

// Adapter is the SPEC §10 tunnel adapter contract.
type Adapter interface {
	// Start brings the path up and reports where callers reach the node.
	Start(ctx context.Context) (Info, error)
	// Status reports the live state; it is safe to call before Start and after Stop.
	Status() Status
	// Stop takes the path down and releases what Start acquired.
	Stop() error
}

// Options every adapter receives; adapter-specific settings arrive via Extra.
type Options struct {
	// PublicBind is the node's local public listener (host:port) the tunnel
	// forwards to; direct simply advertises PublicURL.
	PublicBind string
	// PublicURL is the owner-configured external base (direct) or "" when the
	// adapter allocates one.
	PublicURL string
	// Extra carries the adapter-specific settings, keyed by the names each adapter documents
	// (see the README of this package). A nil map is the same as an empty one.
	Extra map[string]string
}

type factory struct {
	build func(Options) (Adapter, error)
}

var (
	mu        sync.RWMutex
	factories = map[string]factory{}
)

// Register makes an adapter constructible by name and tells core whether it
// terminates TLS at an edge (SPEC §10.1 derivation). Core holds that flag and
// nothing else does: the mode is derived from it in one place (core.Config.Derive).
// The adapters of this package register themselves in init functions; registering a
// name again replaces its factory.
func Register(name string, terminatesAtEdge bool, build func(Options) (Adapter, error)) {
	mu.Lock()
	factories[name] = factory{build: build}
	mu.Unlock()
	core.RegisterTunnel(name, terminatesAtEdge)
}

// New constructs the named adapter. It returns an error naming the registered adapters for an
// unknown name, and the adapter's own error when its options are invalid (each adapter validates
// in its constructor, before any network is touched).
func New(name string, o Options) (Adapter, error) {
	mu.RLock()
	f, ok := factories[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("tunnel: unknown adapter %q (have %v)", name, Names())
	}
	return f.build(o)
}

// Names lists registered adapters, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for n := range factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
