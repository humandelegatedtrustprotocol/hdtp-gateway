package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
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

// SignCard on an identity that holds no key SAYS so. An account that arrived in a
// data-only archive has its root here and its key on the host it left (HDTP §9), and
// the two callers of SignCard — the invite landing page and the manage pages — reach
// it from the network. Without this the person meets a keyring decrypt error about a
// key that was never supposed to be here.
func TestSignCardRefusesWhenTheHostHoldsNoKey(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "nokey.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "moved", DisplayName: "Moved", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, a.ID, "sha256:the-old-host-leaf", nil); err != nil {
		t.Fatal(err)
	}
	_, err = m.SignCard(ctx, a.ID, "BEGIN:VCARD\r\nEND:VCARD\r\n")
	if err == nil {
		t.Fatal("a card was signed by an identity holding no key")
	}
	if !strings.Contains(err.Error(), "holds no key on this host yet") {
		t.Fatalf("the refusal does not name the state: %v", err)
	}
}
