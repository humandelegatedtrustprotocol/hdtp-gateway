package tunnel

import (
	"context"
	"fmt"
	"sync"
)

// Direct is the baseline adapter (SPEC §10.2): the node binds a public port
// itself — port forward, static IP, VPS — and no tunnel process runs. True
// end-to-end mTLS; TerminatesAtEdge is false.
type Direct struct {
	publicURL string
	mu        sync.Mutex
	running   bool
}

func init() {
	Register("direct", false, func(o Options) (Adapter, error) {
		if o.PublicURL == "" {
			return nil, fmt.Errorf("tunnel: direct needs public_url (the externally reachable base)")
		}
		return &Direct{publicURL: o.PublicURL}, nil
	})
}

// Start marks the adapter running and returns the configured PublicURL with TerminatesAtEdge
// false and no Listener. It starts no process and opens no port.
func (d *Direct) Start(ctx context.Context) (Info, error) {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()
	return Info{PublicURL: d.publicURL, TerminatesAtEdge: false}, nil
}

// Status reports the configured PublicURL; Running is whether Start has been called since the last Stop.
func (d *Direct) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{Name: "direct", Running: d.running, PublicURL: d.publicURL,
		Detail: "no tunnel process; the node's own listener is the public endpoint"}
}

// Stop clears the running flag. It always returns nil.
func (d *Direct) Stop() error {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	return nil
}
