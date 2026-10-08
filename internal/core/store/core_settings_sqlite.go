package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// ListSettings returns every owner-set setting row, ordered by key.
func (s *SQLite) ListSettings(ctx context.Context) ([]Setting, error) {
	rows, err := s.q.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Setting, 0, len(rows))
	for _, r := range rows {
		out = append(out, Setting{Key: r.Key, Value: r.Value, Secret: r.Secret != 0, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

// PutSetting inserts or replaces one setting by key.
func (s *SQLite) PutSetting(ctx context.Context, in Setting) error {
	secret := int64(0)
	if in.Secret {
		secret = 1
	}
	return s.q.PutSetting(ctx, sqlitedb.PutSettingParams{
		Key: in.Key, Value: in.Value, Secret: secret, UpdatedAt: in.UpdatedAt,
	})
}

// DeleteSetting removes the setting row for key; one that is not there is not an error.
func (s *SQLite) DeleteSetting(ctx context.Context, key string) error {
	return s.q.DeleteSetting(ctx, key)
}
