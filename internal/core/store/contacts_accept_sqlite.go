package store

import (
	"context"
)

// SetContactAccepted activates a contact and records the card it sent after approval, the
// permissions it granted us and the time of the pin. A contact that is not there is an error.
func (s *SQLite) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	return contactChanged(s.q.SetContactAccepted(ctx, params))
}
