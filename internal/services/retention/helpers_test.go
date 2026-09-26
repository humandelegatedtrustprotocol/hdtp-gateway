package retention

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func migrated(t *testing.T, dir string) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}
