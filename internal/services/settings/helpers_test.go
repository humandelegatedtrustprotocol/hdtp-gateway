package settings

import (
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

func openStoreAt(t *testing.T, dir string) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func openKeyringAt(t *testing.T, dir string) *core.Keyring {
	t.Helper()
	kr, err := core.OpenKeyring(filepath.Join(dir, "keyring.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return kr
}
