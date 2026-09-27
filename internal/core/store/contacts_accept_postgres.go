package store

import (
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	n, err := p.q.SetContactAccepted(ctx, pgdb.SetContactAcceptedParams(params))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}
