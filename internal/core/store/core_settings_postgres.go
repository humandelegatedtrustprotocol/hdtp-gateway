package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
)

// ListSettings returns every owner-set setting row, ordered by key.
func (p *Postgres) ListSettings(ctx context.Context) ([]Setting, error) {
	rows, err := p.q.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Setting, 0, len(rows))
	for _, r := range rows {
		out = append(out, Setting{Key: r.Key, Value: r.Value, Secret: r.Secret, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

// PutSetting inserts or replaces one setting by key.
func (p *Postgres) PutSetting(ctx context.Context, in Setting) error {
	return p.q.PutSetting(ctx, pgdb.PutSettingParams{
		Key: in.Key, Value: in.Value, Secret: in.Secret, UpdatedAt: in.UpdatedAt,
	})
}

// DeleteSetting removes the setting row for key; one that is not there is not an error.
func (p *Postgres) DeleteSetting(ctx context.Context, key string) error {
	return p.q.DeleteSetting(ctx, key)
}
