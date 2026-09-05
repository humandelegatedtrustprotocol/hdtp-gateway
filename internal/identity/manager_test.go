package identity

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func TestManagerCreateAccountSealsAndBinds(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(dir, "k"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: kr}

	a, err := m.CreateAccount(context.Background(), "work", "Work", AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint == "" {
		t.Fatal("no fingerprint bound")
	}
	got, _ := st.GetAccountBySlug(context.Background(), "work")
	if got.Fingerprint != a.Fingerprint {
		t.Fatal("fingerprint not persisted")
	}
}
