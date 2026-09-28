package store

import (
	"context"
	"database/sql"

	"github.com/pact-cloud/pact-gateway/internal/core/store/sqlitedb"
)

// fillLeafFingerprints gives every row holding a leaf and no fingerprint of it the fingerprint of
// the leaf's key (migration 0046's column). Migrate runs it after every Up on both engines: the
// first time it fills the rows held before 0046, and afterwards it finds none, because every
// statement that writes a leaf writes the fingerprint with it (leafFingerprint). One Go function
// for both engines, because SQLite has no SHA-256 and two copies of the computation would drift.
// A crash part-way leaves the rest for the next start.
func fillLeafFingerprints(ctx context.Context,
	list func(context.Context) ([]sqlitedb.ListContactLeafKeysUnfilledRow, error),
	set func(context.Context, sql.NullString, string) error,
) error {
	rows, err := list(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := set(ctx, keyFingerprint(r.Spki), r.ID); err != nil {
			return err
		}
	}
	return nil
}
