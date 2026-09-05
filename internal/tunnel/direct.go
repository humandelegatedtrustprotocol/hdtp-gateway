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

func (d *Direct) Start(ctx context.Context) (Info, error) {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()
	return Info{PublicURL: d.publicURL, TerminatesAtEdge: false}, nil
}

func (d *Direct) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{Name: "direct", Running: d.running, PublicURL: d.publicURL,
		Detail: "no tunnel process; the node's own listener is the public endpoint"}
}

func (d *Direct) Stop() error {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	return nil
}
