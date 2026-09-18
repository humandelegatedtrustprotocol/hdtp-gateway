package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (p *Postgres) SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error {
	if theirPermissions == nil {
		theirPermissions = []string{}
	}
	raw, err := json.Marshal(theirPermissions)
	if err != nil {
		return err
	}
	n, err := p.q.SetContactAccepted(ctx, pgdb.SetContactAcceptedParams{
		Card: card, TheirPermissions: string(raw), PinnedAt: pgtype.Int8{Int64: now, Valid: true},
		AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}
