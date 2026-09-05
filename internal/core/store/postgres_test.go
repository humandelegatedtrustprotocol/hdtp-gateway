package store_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/core/store/conformance"
)

// TestPostgresConformance runs the same suite as SQLite against a real Postgres,
// gated by PACT_TEST_POSTGRES_DSN (CI sets it via a service container; locally:
// docker compose -f compose.test.yaml up -d). Each subtest gets a fresh database.
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
