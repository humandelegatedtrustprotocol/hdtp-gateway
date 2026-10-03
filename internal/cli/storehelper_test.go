package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// migrated opens a SQLite store in dir and brings it up to date. It lived in the
// relay wiring's test file until the relay role was
// removed; several other tests here depend on it, so it has its own file now
// rather than riding along with whatever happens to survive next.
func migrated(t *testing.T, dir string) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}
