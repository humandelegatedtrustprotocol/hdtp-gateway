package ingress

import (
	"context"

	"github.com/caddyserver/certmagic"
)

// Renew forces a renewal now and reloads the renewed certificate into the serving
// cache. Test-only: in production certmagic renews every managed name on its own
// once Manage has been called; this lets the renewal test make one happen at once.
func (a *ACME) Renew(ctx context.Context, name string) error {
	if err := a.cfg.RenewCertSync(ctx, name, true); err != nil {
		return err
	}
	// swap, don't accumulate: evict the name's cached entries, then load the
	// renewed certificate from storage so serving switches over immediately
	a.cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: name}})
	_, err := a.cfg.CacheManagedCertificate(ctx, name)
	return err
}
