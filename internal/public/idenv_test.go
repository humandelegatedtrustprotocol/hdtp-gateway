package public

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// The shared environment these tests decide against: a store, one account, and an
// Identifier wired to them on a fixed clock.
//
// It lived in `identify_test.go`, which tested the `v: 1` open order and went with
// it. Several suites here depend on it, so it has its own file rather than riding
// along with whatever happens to survive next.

var fixedNow = time.Unix(1756000000, 0)

type idEnv struct {
	id      *Identifier
	st      store.Store
	acct    store.Account
	acctKP  *identity.Keypair
	senders map[string]*identity.Keypair
}

func newIdEnv(t *testing.T, algo identity.Algo) *idEnv {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: string(algo)})
	if err := st.SetAccountKey(ctx, a.ID, kp.Fingerprint, []byte{1}); err != nil {
		t.Fatal(err)
	}
	a, _ = st.GetAccountByID(ctx, a.ID)
	return &idEnv{
		st: st, acct: a, acctKP: kp, senders: map[string]*identity.Keypair{},
		id: &Identifier{
			Store:   st,
			Keypair: func(context.Context, string) (*identity.Keypair, error) { return kp, nil },
			Seal:    core.SealRequired, Cert: core.ClientCertPreferred,
			Now: func() time.Time { return fixedNow },
		},
	}
}

func (e *idEnv) sender(t *testing.T, name string, algo identity.Algo) *identity.Keypair {
	t.Helper()
	if kp, ok := e.senders[name]; ok {
		return kp
	}
	kp, err := identity.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	e.senders[name] = kp
	return kp
}

func spkiOf(t *testing.T, kp *identity.Keypair) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
