package store

import (
	"context"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
)

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

func (p *Postgres) PutSetting(ctx context.Context, in Setting) error {
	return p.q.PutSetting(ctx, pgdb.PutSettingParams{
		Key: in.Key, Value: in.Value, Secret: in.Secret, UpdatedAt: in.UpdatedAt,
	})
}

func (p *Postgres) DeleteSetting(ctx context.Context, key string) error {
	return p.q.DeleteSetting(ctx, key)
}
