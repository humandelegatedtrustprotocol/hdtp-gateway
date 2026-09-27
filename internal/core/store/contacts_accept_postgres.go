package store

import (
	"context"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	return contactChanged(p.q.SetContactAccepted(ctx, pgdb.SetContactAcceptedParams(params)))
}
