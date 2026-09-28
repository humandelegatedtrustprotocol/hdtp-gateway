package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// A lease is one holder's at a time (SPEC §11.1): taken by the first to ask, renewed by its holder,
// refused to another while it has not run out, and anyone's once it has — on both engines.
func TestALeaseIsOneHoldersUntilItRunsOut(t *testing.T) {
	engines := map[string]store.Store{}
	sq, err := store.OpenSQLite(filepath.Join(t.TempDir(), "lease.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	if err := sq.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	engines["sqlite"] = sq
	if dsn := os.Getenv("PACT_TEST_POSTGRES_DSN"); dsn != "" {
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS pact_leases")
		if _, err := admin.Exec(ctx, "CREATE DATABASE pact_leases"); err != nil {
			t.Fatal(err)
		}
		admin.Close(ctx)
		pg, err := store.OpenPostgres(ctx, rewriteDB(dsn, "pact_leases"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pg.Close() })
		if err := pg.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		engines["postgres"] = pg
	}
	for engine, st := range engines {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			take := func(holder string, now, until int64) bool {
				t.Helper()
				ok, err := st.TakeLease(ctx, "retries", holder, now, until)
				if err != nil {
					t.Fatal(err)
				}
				return ok
			}
			if !take("a", 100, 145) {
				t.Fatal("a free lease was refused")
			}
			if take("b", 120, 165) {
				t.Fatal("a lease another holds and has not let run out was taken")
			}
			if !take("a", 140, 185) {
				t.Fatal("the holder could not renew its own lease")
			}
			if take("b", 180, 225) {
				t.Fatal("a renewed lease was taken before it ran out")
			}
			if !take("b", 186, 231) {
				t.Fatal("a lease that ran out was not anyone's")
			}
			if take("a", 190, 235) {
				t.Fatal("the former holder took back a lease another holds")
			}
			if ok, err := st.TakeLease(ctx, "retention", "a", 190, 235); err != nil || !ok {
				t.Fatalf("another lease was refused to a holder of none of it: %v %v", ok, err)
			}
		})
	}
}
