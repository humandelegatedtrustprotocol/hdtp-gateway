package store

// What one store read costs. The envelope path reads the account row, the leaf
// ledger and the pins on every inbound call, so this is the floor under every
// per-request number in the node.

import (
	"context"
	"path/filepath"
	"testing"
)

func benchStore(b *testing.B) (*SQLite, Account) {
	b.Helper()
	st, err := OpenSQLite(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, CreateAccountParams{Slug: "bench", DisplayName: "Bench", Algo: "p256"})
	if err != nil {
		b.Fatal(err)
	}
	return st, a
}

func BenchmarkGetAccountByID(b *testing.B) {
	st, a := benchStore(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.GetAccountByID(ctx, a.ID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkListLeaves(b *testing.B) {
	st, a := benchStore(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.ListLeaves(ctx, a.ID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkListAccounts(b *testing.B) {
	st, _ := benchStore(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.ListAccounts(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
