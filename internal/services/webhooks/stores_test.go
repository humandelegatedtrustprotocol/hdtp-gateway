package webhooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Copied from internal/messaging/bus_test.go: the engines a multi-process test runs on.

// sharedStores opens n handles on one store — n node processes sharing it — for each engine the
// test machine has: one SQLite file always, one Postgres database when HDTP_TEST_POSTGRES_DSN is
// set (the pre-push hook sets it).
func sharedStores(t *testing.T, n int) map[string][]store.Store {
	t.Helper()
	ctx := context.Background()
	out := map[string][]store.Store{}
	path := filepath.Join(t.TempDir(), "shared.db")
	for i := 0; i < n; i++ {
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if i == 0 {
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		out["sqlite"] = append(out["sqlite"], st)
	}
	dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
	if dsn == "" {
		return out
	}
	db := "hdtp_wh_" + strings.ToLower(strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	i := strings.LastIndex(dsn, "/")
	target := dsn[:i+1] + db
	if j := strings.Index(dsn[i+1:], "?"); j >= 0 {
		target += dsn[i+1:][j:]
	}
	for k := 0; k < n; k++ {
		st, err := store.OpenPostgres(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if k == 0 {
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		out["postgres"] = append(out["postgres"], st)
	}
	return out
}
