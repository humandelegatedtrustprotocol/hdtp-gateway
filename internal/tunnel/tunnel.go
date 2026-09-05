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

	"github.com/tech-sumit/pact-gateway/internal/core"
)

// Info is what Start reports back (SPEC §10: Start → {PublicURL, TerminatesAtEdge}).
type Info struct {
	PublicURL        string
	TerminatesAtEdge bool
	// Listener, when non-nil, is the raw stream the adapter delivers callers on
	// (tailscale, frp, ngrok): the node runs its OWN TLS on it, so client
	// certificates stay visible end to end (SPEC §10.2). Direct leaves it nil —
	// the node's own bind is the public endpoint.
	Listener net.Listener
}

// Status is the adapter's live state for the portal/doctor.
type Status struct {
	Name      string `json:"name"`
	Running   bool   `json:"running"`
	PublicURL string `json:"public_url,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Adapter is the SPEC §10 tunnel adapter contract.
type Adapter interface {
	Start(ctx context.Context) (Info, error)
	Status() Status
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
	Extra     map[string]string
}

type factory struct {
	terminatesAtEdge bool
	build            func(Options) (Adapter, error)
}

var (
	mu        sync.RWMutex
	factories = map[string]factory{}
)

// Register makes an adapter constructible by name and tells core whether it
// terminates TLS at an edge (SPEC §10.1 derivation).
func Register(name string, terminatesAtEdge bool, build func(Options) (Adapter, error)) {
	mu.Lock()
	factories[name] = factory{terminatesAtEdge: terminatesAtEdge, build: build}
	mu.Unlock()
	core.RegisterTunnel(name, terminatesAtEdge)
}

// New constructs the named adapter.
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

// TerminatesAtEdge reports the registered adapter's edge flag.
func TerminatesAtEdge(name string) (bool, error) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := factories[name]
	if !ok {
		return false, fmt.Errorf("tunnel: unknown adapter %q", name)
	}
	return f.terminatesAtEdge, nil
}
