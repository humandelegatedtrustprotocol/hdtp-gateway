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

// Cloudflare wraps the libdns Cloudflare provider. Only Provider is used by the caller
// (through Solver); Zone and TTL are recorded by NewCloudflare and read by no non-test code in this
// repository (a search for them found none).
type Cloudflare struct {
	// Provider is the libdns provider, holding the API token.
	Provider *cloudflare.Provider
	// Zone is the zone name with a trailing dot: NewCloudflare appends one if it is missing.
	Zone string
	// TTL is set to five minutes by NewCloudflare.
	TTL time.Duration
}

// NewCloudflare returns the adapter for zone, authenticated with apiToken, which needs
// Zone.DNS:Write for the zone. It refuses an empty token and an empty zone with an error;
// it makes no network call, so a wrong token is found when certmagic first solves a challenge.
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

// Solver returns the libdns provider for certmagic's DNS01Solver, the only way to obtain a
// wildcard certificate; ingress.ACMEOptions.DNS takes it.
func (c *Cloudflare) Solver() *cloudflare.Provider { return c.Provider }
