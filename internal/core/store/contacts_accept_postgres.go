package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
)

// SetContactAccepted activates a contact and records the card it sent after approval, the
// permissions it granted us and the time of the pin. A contact that is not there is an error.
func (p *Postgres) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	return contactChanged(p.q.SetContactAccepted(ctx, pgdb.SetContactAcceptedParams(params)))
}
