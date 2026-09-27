package store

import (
	"context"
	"fmt"
)

func (s *SQLite) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	params, err := contactAccepted(accountID, fingerprint, card, theirPermissions, now)
	if err != nil {
		return err
	}
	n, err := s.q.SetContactAccepted(ctx, params)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}
