package store

import (
	"context"
)

func (s *SQLite) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	return contactChanged(s.q.SetContactAccepted(ctx, params))
}
