package store_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3/lock"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/core/store/conformance"
)

// TestPostgresConformance runs the same suite as SQLite against a real Postgres,
// gated by PACT_TEST_POSTGRES_DSN (the pre-push hook starts a named Postgres
// container and sets it; by hand: docker compose -f compose.test.yaml up -d). Each subtest gets a fresh database.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PACT_TEST_POSTGRES_DSN not set")
	}
	n := 0
	conformance.Run(t, func(t *testing.T) conformance.Migratable {
		n++
		dbName := fmt.Sprintf("pact_conf_%d", n)
		admin, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		// throwaway per-test database on the test server
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
		if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+dbName); err != nil {
			t.Fatal(err)
		}
		admin.Close(context.Background())

		testDSN := rewriteDB(dsn, dbName)
		s, err := store.OpenPostgres(context.Background(), testDSN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

// rewriteDB swaps the database name in a postgres URL DSN.
func rewriteDB(dsn, db string) string {
	i := strings.LastIndex(dsn, "/")
	rest := dsn[i+1:]
	if j := strings.Index(rest, "?"); j >= 0 {
		return dsn[:i+1] + db + rest[j:]
	}
	return dsn[:i+1] + db
}

// Many node processes on many hosts share one Postgres and each migrates as it starts (SPEC
// §11.1): they take turns under the migration's session-level advisory lock. Held by another
// session — another process migrating — a Migrate waits, touching nothing, and runs once it is
// released; processes started together all succeed.
func TestPostgresMigrationsTakeTurns(t *testing.T) {
	dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PACT_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	const dbName = "pact_migrate_turns"
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)

	// Another process, mid-migration: it holds the lock.
	other, err := pgx.Connect(ctx, rewriteDB(dsn, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	if _, err := other.Exec(ctx, "SELECT pg_advisory_lock($1)", lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}
	const processes = 4
	errs := make(chan error, processes)
	stores := make([]*store.Postgres, processes)
	for i := range stores {
		st, err := store.OpenPostgres(ctx, rewriteDB(dsn, dbName))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		stores[i] = st
	}
	for _, st := range stores {
		go func(st *store.Postgres) { errs <- st.Migrate(ctx) }(st)
	}
	time.Sleep(2 * time.Second)
	select {
	case err := <-errs:
		t.Fatalf("a migration ran while another process held the migration lock: %v", err)
	default:
	}
	if err := stores[0].SchemaCurrent(ctx); err == nil {
		t.Fatal("the schema moved while another process held the migration lock")
	}
	if _, err := other.Exec(ctx, "SELECT pg_advisory_unlock($1)", lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}
	for range stores {
		if err := <-errs; err != nil {
			t.Fatalf("a migration started beside others failed: %v", err)
		}
	}
	for _, st := range stores {
		if err := st.SchemaCurrent(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
