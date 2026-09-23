// Package dns holds the ingress role's DNS adapter (SPEC §10.6): it answers ACME
// DNS-01 for the wildcard certificate. No per-pairing record is ever written — the
// owner points the wildcard at the ingress once. Cloudflare, via the libdns
// provider certmagic's DNS-01 solver consumes. Off-the-shelf on purpose.
package dns

import (
	"fmt"
	"strings"
	"time"

	"github.com/libdns/cloudflare"
)

// Cloudflare wraps the libdns Cloudflare provider.
type Cloudflare struct {
	Provider *cloudflare.Provider
	Zone     string // "example.com." (trailing dot optional)
	TTL      time.Duration
}

// NewCloudflare needs an API token with Zone.DNS:Write for the zone.
func NewCloudflare(apiToken, zone string) (*Cloudflare, error) {
	if apiToken == "" {
		return nil, fmt.Errorf("dns: cloudflare needs an API token with Zone.DNS:Write")
	}
	if zone == "" {
		return nil, fmt.Errorf("dns: cloudflare needs the zone name")
	}
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return &Cloudflare{Provider: &cloudflare.Provider{APIToken: apiToken}, Zone: zone, TTL: 5 * time.Minute}, nil
}

// Solver returns the libdns provider for certmagic's DNS01Solver (wildcards).
func (c *Cloudflare) Solver() *cloudflare.Provider { return c.Provider }
