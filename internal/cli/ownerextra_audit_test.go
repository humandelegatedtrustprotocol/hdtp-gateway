package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/audit"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// chainMustNotBeRead fails the test if anything asks for the whole audit chain. The owner MCP's
// `audit_query` did, on every call, and cut it down afterwards: every row of the trail in memory
// to answer a question that is bounded by design.
type chainMustNotBeRead struct {
	store.Store
	t *testing.T
}

func (s chainMustNotBeRead) ListAuditEvents(context.Context, string) ([]store.AuditRow, error) {
	s.t.Fatal("audit_query read the whole chain; it must ask the store for a page")
	return nil, nil
}

func TestTheOwnersAuditQueryReadsAPageAndNeverTheChain(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	b, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "bharat", DisplayName: "Bharat", Algo: "p256"})
	w := &audit.Writer{Sink: store.AuditAppender{St: st}}
	write := func(accountID, actor, action string) {
		t.Helper()
		if err := w.Append(ctx, accountID, "owner", actor, action, "r", "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		write(a.ID, "owner-a", fmt.Sprintf("alina-%d", i))
	}
	write(b.ID, "owner-b", "bharat-0")
	// Then the node has a long, busy stretch of its own: far more rows than any page asked for.
	for i := 0; i < 300; i++ {
		write("", "system", fmt.Sprintf("node-%d", i))
	}
	guarded := chainMustNotBeRead{Store: st, t: t}
	actions := func(rows []store.AuditRow) []string {
		out := []string{}
		for _, r := range rows {
			out = append(out, r.Action)
		}
		return out
	}

	// Scoped to Alina's account: her five rows, oldest first, although three hundred rows of the
	// node's own sit on top of them and none of Bharat's or the node's may be shown.
	onlyA := func(id string) bool { return id == a.ID }
	rows, err := auditPageFor(ctx, guarded, "", 5, onlyA)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(actions(rows)), "[alina-0 alina-1 alina-2 alina-3 alina-4]"; got != want {
		t.Fatalf("scoped to one account: %s, want %s", got, want)
	}

	// A caller who administers the node sees its rows too: the newest five, oldest of them first.
	rows, err = auditPageFor(ctx, guarded, "", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(actions(rows)), "[node-295 node-296 node-297 node-298 node-299]"; got != want {
		t.Fatalf("node-wide: %s, want %s", got, want)
	}

	// By actor: the rows that actor wrote, through the index on it, and within what is permitted.
	rows, err = auditPageFor(ctx, guarded, "owner-b", 10, nil)
	if err != nil || fmt.Sprint(actions(rows)) != "[bharat-0]" {
		t.Fatalf("by actor: %v %v, want [bharat-0]", actions(rows), err)
	}
	if rows, _ = auditPageFor(ctx, guarded, "owner-b", 10, onlyA); len(rows) != 0 {
		t.Fatalf("an actor's rows in an account this caller may not read were shown: %v", actions(rows))
	}
}
