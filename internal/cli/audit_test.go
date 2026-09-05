package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// seedAudit migrates a store in dir/data and appends n chained events.
func seedAudit(t *testing.T, dir string, n int) string {
	t.Helper()
	dataDir := filepath.Join(dir, "data")
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run(t, "migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	clock := time.Unix(1756000000, 0)
	w := &audit.Writer{Sink: st, Now: func() time.Time { return clock }}
	for i := 0; i < n; i++ {
		if err := w.Append(context.Background(), "acct", "owner", "o1", "settings_update", "account:acct", "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return cfgPath
}

func TestAuditExportThenVerifyGreen(t *testing.T) {
	cfgPath := seedAudit(t, t.TempDir(), 4)

	code, out, errb := run(t, "audit", "verify", "-config", cfgPath)
	if code != 0 || !strings.Contains(out, "4 events, intact") {
		t.Fatalf("verify: code=%d out=%q err=%q", code, out, errb)
	}
	code, out, _ = run(t, "audit", "export", "-config", cfgPath)
	if code != 0 {
		t.Fatalf("export: %d", code)
	}
	// the export is a JSONL archive that re-verifies as one chain
	events, err := audit.ImportJSONL(strings.NewReader(out))
	if err != nil || len(events) != 4 {
		t.Fatalf("import: %v %d", err, len(events))
	}
	if idx, err := audit.Verify(events); err != nil {
		t.Fatalf("exported chain broken at %d: %v", idx, err)
	}
}

func TestAuditTamperedExportDetected(t *testing.T) {
	cfgPath := seedAudit(t, t.TempDir(), 3)
	_, out, _ := run(t, "audit", "export", "-config", cfgPath)
	events, err := audit.ImportJSONL(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	events[1].Details = `{"forged":true}` // tamper mid-chain
	idx, err := audit.Verify(events)
	if err == nil || idx != 1 {
		t.Fatalf("tamper not caught: idx=%d err=%v", idx, err)
	}
	// round-trip the tamper through JSONL too
	var b strings.Builder
	_ = audit.ExportJSONL(&b, events)
	re, _ := audit.ImportJSONL(strings.NewReader(b.String()))
	if _, err := audit.Verify(re); err == nil {
		t.Fatal("tampered archive verified")
	}
	var e audit.Event
	_ = json.Unmarshal([]byte(strings.SplitN(b.String(), "\n", 2)[0]), &e)
	if e.Seq != 1 {
		t.Fatalf("archive order: %+v", e)
	}
}

func TestAuditRefusedWhileNodeRunning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := seedAudit(t, dir, 1)
	lock, err := core.AcquireLock(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	code, _, errb := run(t, "audit", "verify", "-config", cfgPath)
	if code == 0 || !strings.Contains(errb, "in use") {
		t.Fatalf("audit ran under a held lock: code=%d err=%q", code, errb)
	}
}

// AC (P7-05): archiving moves old rows to a JSONL file and RE-ANCHORS what is
// left, so `audit verify` spans the archive plus the live table as one chain
// (SPEC §11.6). The dangerous failure is the opposite: rows removed with no
// anchor recorded, leaving a shorter chain that still verifies.
func TestAuditArchivePrunesAndKeepsTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "d")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runQuiet("migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	w := &audit.Writer{Sink: st}
	for i := 0; i < 10; i++ {
		if err := w.Append(ctx, "", "system", "", "probe", fmt.Sprintf("row:%d", i), "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	if code, out, errb := runQuiet("audit", "verify", "-config", cfgPath); code != 0 {
		t.Fatalf("verify before archive: %s %s", out, errb)
	}
	// archive the first six
	code, out, errb := runQuiet("audit", "archive", "-config", cfgPath, "-through", "6")
	if code != 0 || !strings.Contains(out, "archived 6 events") {
		t.Fatalf("archive: code=%d out=%q err=%q", code, out, errb)
	}
	// the rows are gone from the table…
	st, _ = store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("after pruning, %d rows remain, want 4", len(rows))
	}
	anchor, err := st.AuditAnchor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.ArchivedThroughSeq != 6 || anchor.TerminalHash == "" {
		t.Fatalf("the anchor was not recorded: %+v", anchor)
	}
	st.Close()

	// …and the chain still verifies, across the archive and what is left
	if code, out, errb := runQuiet("audit", "verify", "-config", cfgPath); code != 0 {
		t.Fatalf("verify after archive: %s %s", out, errb)
	} else if !strings.Contains(out, "archive") {
		t.Fatalf("verify did not report spanning the archive: %q", out)
	}

	// a tampered archive file is detected
	files, _ := filepath.Glob(filepath.Join(dataDir, "audit", "audit-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("archives: %v", files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], []byte(strings.Replace(string(raw), "row:2", "row:X", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runQuiet("audit", "verify", "-config", cfgPath); code == 0 {
		t.Fatalf("a tampered archive verified as intact: %q", out)
	}
	if err := os.WriteFile(files[0], raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Pruning beyond the anchor is refused by the ENGINE, not by convention:
	// only rows an archive has already captured may be removed. (The anchored
	// verify in TestHeadTruncationIsDetected covers the case where rows are
	// removed some other way, e.g. by editing the database directly.)
	st, _ = store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	_, err = st.DeleteAuditEventsThrough(ctx, 7)
	st.Close()
	if err == nil {
		t.Fatal("rows past the anchor were pruned: the append-only guard is not holding")
	}
	if !strings.Contains(err.Error(), "archived and anchored") {
		t.Fatalf("the refusal should name the rule: %v", err)
	}
	// the chain is still intact after that refusal
	if code, out, errb := runQuiet("audit", "verify", "-config", cfgPath); code != 0 {
		t.Fatalf("verify after a refused prune: %s %s", out, errb)
	}
}

// AC (P9-05, H3/H4): the anchor is what makes pruning safe, so the anchor needs
// guarding too. A wiped chain, a missing archive and a backwards anchor must all
// be reported — a forged anchor plus a delete used to make a complete audit wipe
// verify clean.
func TestAuditAnchorCannotBeUsedToHideAWipe(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "d")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runQuiet("migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	w := &audit.Writer{Sink: st}
	for i := 0; i < 6; i++ {
		if err := w.Append(ctx, "", "system", "", "probe", fmt.Sprintf("r:%d", i), "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}

	// forge an anchor that claims everything is archived, then wipe the table
	if err := st.SetAuditAnchor(ctx, store.AuditAnchorRow{
		ArchivedThroughSeq: 1 << 40, TerminalHash: "forged", ArchivePath: "", UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteAuditEventsThrough(ctx, 1<<40); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if code, out, _ := runQuiet("audit", "verify", "-config", cfgPath); code == 0 {
		t.Fatalf("a wiped chain verified clean under a forged anchor: %q", out)
	}

	// and the anchor may not be walked backward to fake a break either
	st, _ = store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	defer st.Close()
	if err := st.SetAuditAnchor(ctx, store.AuditAnchorRow{
		ArchivedThroughSeq: 1, TerminalHash: "older", UpdatedAt: 2,
	}); err == nil {
		t.Fatal("the audit anchor was moved backward")
	}
}

// AC (P9-05, H3): the archive is part of the chain, so losing it is losing the
// chain — not a reason to report success.
func TestVerifyFailsWhenTheArchiveIsGone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "d")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runQuiet("migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	w := &audit.Writer{Sink: st}
	for i := 0; i < 8; i++ {
		if err := w.Append(ctx, "", "system", "", "probe", fmt.Sprintf("r:%d", i), "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if code, _, errb := runQuiet("audit", "archive", "-config", cfgPath, "-through", "5"); code != 0 {
		t.Fatalf("archive: %s", errb)
	}
	if code, _, _ := runQuiet("audit", "verify", "-config", cfgPath); code != 0 {
		t.Fatal("verify failed right after archiving")
	}
	// lose the archive
	files, _ := filepath.Glob(filepath.Join(dataDir, "audit", "*.jsonl"))
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, _ := runQuiet("audit", "verify", "-config", cfgPath); code == 0 {
		t.Fatalf("verify reported success with the archived history gone: %q", out)
	}
}
