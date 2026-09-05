// Package dns holds the ingress role's DNS adapters (SPEC §10.6): create and
// update subdomain records pointing at the ingress, and answer ACME DNS-01 for
// wildcard certificates. Cloudflare first — via the libdns provider, which is
// also what certmagic's DNS-01 solver consumes. Off-the-shelf on purpose.
package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
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

// Point sets <sub>.<zone> → ip (A or AAAA) so callers reach the ingress.
func (c *Cloudflare) Point(ctx context.Context, sub string, ip netip.Addr) error {
	rec := libdns.Address{Name: sub, TTL: c.TTL, IP: ip}
	_, err := c.Provider.SetRecords(ctx, c.Zone, []libdns.Record{rec})
	if err != nil {
		return fmt.Errorf("dns: cloudflare set %s: %w", sub, err)
	}
	return nil
}

// Solver returns the libdns provider for certmagic's DNS01Solver (wildcards).
func (c *Cloudflare) Solver() *cloudflare.Provider { return c.Provider }
