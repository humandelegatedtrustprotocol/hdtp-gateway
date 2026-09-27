package auditsink

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// AC (P8-01, defect #2): every audit write must carry an actor kind the store
// accepts. A kind outside owner|token|contact|guest|cli|system fails the CHECK
// constraint and the append is LOST — which is what happened silently between
// P6-03 and P7-01, reported only to stderr that nothing read. The sink clamps to
// `system` rather than emitting a row that dies on the way in.
func TestAuditActorKindIsAlwaysWritable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	sink := New(ctx, st, &stderr)
	kinded := sink.Kinded()

	// in-set kinds are written verbatim; anything else degrades to `system`
	for _, kind := range []string{"owner", "token", "contact", "guest", "cli", "system"} {
		kinded(kind, "probe", "resource:"+kind, "ok")
	}
	for _, bad := range []string{"peer", "", "PENDING", "admin", "root", "Owner"} {
		kinded(bad, "probe_bad", "resource:"+bad, "ok")
	}

	// stderr now carries the live event mirror as well as failures, so "empty" is
	// no longer the same question. A FAILURE is the line prefixed `audit:`.
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "audit:") {
			t.Fatalf("an audit append failed instead of being clamped: %s", line)
		}
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 12 {
		t.Fatalf("wrote %d rows, want 12 — a rejected append is a hole in the chain", len(rows))
	}
	allowed := map[string]bool{
		"owner": true, "token": true, "contact": true, "guest": true, "cli": true, "system": true,
	}
	clamped := 0
	for _, r := range rows {
		if !allowed[r.ActorKind] {
			t.Fatalf("row stored with an actor kind the schema forbids: %+v", r)
		}
		if r.Action == "probe_bad" {
			if r.ActorKind != "system" {
				t.Fatalf("an out-of-set kind became %q, want system: %+v", r.ActorKind, r)
			}
			clamped++
		}
	}
	if clamped != 6 {
		t.Fatalf("clamped %d rows, want 6", clamped)
	}
}
