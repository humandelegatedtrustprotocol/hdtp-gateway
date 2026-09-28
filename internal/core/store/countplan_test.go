package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The owner's wait counts the requests awaiting approval on every wake (CountContactsByStatus).
// The count must read the rows in that state alone — the account and the state together, from
// contacts_account_status — and not every contact of the account, which is what an index on the
// account alone would give.
func TestCountingContactsByStatusReadsThoseRowsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+strings.TrimSuffix(strings.TrimSpace(countContactsByStatusSQL(t)), ";"), "a", "pending_in")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, "; ")
	if !strings.Contains(joined, "contacts_account_status (account_id=? AND status=?)") {
		t.Fatalf("the count does not read by account and state together: %s", joined)
	}
}

// countContactsByStatusSQL is the statement as queries/sqlite/contacts.sql writes it.
func countContactsByStatusSQL(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "queries", "sqlite", "contacts.sql"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "-- name: CountContactsByStatus :one")
	if i < 0 {
		t.Fatal("queries/sqlite/contacts.sql has no CountContactsByStatus")
	}
	var stmt []string
	for _, line := range strings.Split(src[i:], "\n")[1:] {
		if strings.HasPrefix(line, "--") {
			continue
		}
		stmt = append(stmt, line)
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			break
		}
	}
	return strings.Join(stmt, " ")
}
