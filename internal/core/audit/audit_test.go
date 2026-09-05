package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func ev(i int64, action string) Event {
	return Event{
		Seq: i, TS: 1756000000 + i, AccountID: "acct1",
		ActorKind: "contact", ActorID: "sha256:abc", Action: action,
		Resource: "tool:send_message", Outcome: "ok", RequestID: "r1",
		Details: `{"n":` + string(rune('0'+i%10)) + `}`,
	}
}

func buildChain(t *testing.T, n int64) []Event {
	t.Helper()
	events := make([]Event, 0, n)
	prev := GenesisHash
	for i := int64(1); i <= n; i++ {
		e := ev(i, "tools/call")
		e.PrevHash = prev
		h, err := HashEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		e.Hash = h
		prev = h
		events = append(events, e)
	}
	return events
}

func TestGenesisIsZeroBytes(t *testing.T) {
	if GenesisHash != strings.Repeat("0", 64) {
		t.Fatalf("genesis = %q", GenesisHash)
	}
}

func TestHashDeterministicAndLowercaseHex(t *testing.T) {
	e := ev(1, "x")
	e.PrevHash = GenesisHash
	h1, err := HashEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashEvent(e)
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if len(h1) != 64 || strings.ToLower(h1) != h1 {
		t.Fatalf("hash not lowercase hex-64: %q", h1)
	}
}

func TestVerifyCleanChain(t *testing.T) {
	events := buildChain(t, 50)
	if idx, err := Verify(events); err != nil {
		t.Fatalf("clean chain reported break at %d: %v", idx, err)
	}
}

func TestVerifyDetectsSingleByteTamper(t *testing.T) {
	events := buildChain(t, 20)
	// flip one byte in row 7's details
	events[7].Details = strings.Replace(events[7].Details, "{", "[", 1)
	idx, err := Verify(events)
	if err == nil {
		t.Fatal("tamper not detected")
	}
	if idx != 7 {
		t.Fatalf("break reported at %d, want 7", idx)
	}
}

func TestVerifyDetectsReorderAndDeletion(t *testing.T) {
	events := buildChain(t, 10)
	swapped := append([]Event{}, events...)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	if _, err := Verify(swapped); err == nil {
		t.Fatal("reorder not detected")
	}
	pruned := append(append([]Event{}, events[:5]...), events[6:]...)
	if _, err := Verify(pruned); err == nil {
		t.Fatal("deletion not detected")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	events := buildChain(t, 10)
	var buf bytes.Buffer
	if err := ExportJSONL(&buf, events); err != nil {
		t.Fatal(err)
	}
	got, err := ImportJSONL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("round trip lost rows: %d != %d", len(got), len(events))
	}
	if _, err := Verify(got); err != nil {
		t.Fatalf("imported chain does not verify: %v", err)
	}
}

func TestReanchoredArchivePlusLiveVerifiesAsOneChain(t *testing.T) {
	events := buildChain(t, 30)
	archived, live := events[:20], events[20:]

	var buf bytes.Buffer
	if err := ExportJSONL(&buf, archived); err != nil {
		t.Fatal(err)
	}
	// §11.6: the first live row's PrevHash records the archived segment's terminal
	// hash — which buildChain already guarantees. Verification must span both.
	back, err := ImportJSONL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if idx, err := Verify(append(back, live...)); err != nil {
		t.Fatalf("archive+live chain broke at %d: %v", idx, err)
	}
	// tampering inside the ARCHIVE must still be detected
	back[3].Outcome = "denied"
	if _, err := Verify(append(back, live...)); err == nil {
		t.Fatal("archive tamper not detected")
	}
}

func TestCanonicalJSONIsStableAndUnescaped(t *testing.T) {
	e := ev(1, `msg with <html> & "quotes"`)
	e.PrevHash = GenesisHash
	b1, err := canonicalRow(e)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b1, []byte(`\u003c`)) || !bytes.Contains(b1, []byte(`<`)) {
		t.Fatal("canonical JSON must not HTML-escape: raw '<' should survive")
	}
	if bytes.Contains(b1, []byte(" ")) && !bytes.Contains([]byte(e.Action), []byte(" ")) {
		t.Fatal("canonical JSON must not contain insignificant whitespace")
	}
	// keys must appear in sorted order
	keys := []string{"account_id", "action", "actor_id", "actor_kind", "details",
		"outcome", "request_id", "resource", "seq", "ts", "v"}
	last := -1
	for _, k := range keys {
		i := bytes.Index(b1, []byte(`"`+k+`"`))
		if i < 0 {
			t.Fatalf("key %q missing from canonical row", k)
		}
		if i < last {
			t.Fatalf("key %q out of sorted order", k)
		}
		last = i
	}
}

// AC (P7-05): the chain must detect a truncated HEAD. Verify anchors on whatever
// the first row claims, so deleting the oldest rows leaves a shorter chain that
// still verifies — an attacker who can reach the database removes the evidence
// of arriving and the log reports itself intact. An anchored verify is what
// makes pruning safe enough to add at all (SPEC §11.4, §11.6).
func TestHeadTruncationIsDetected(t *testing.T) {
	var events []Event
	prev := GenesisHash
	for i := 1; i <= 5; i++ {
		e := Event{Seq: int64(i), TS: int64(1700000000 + i), ActorKind: "system", Action: "probe"}
		filled, err := Next(prev, e)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, filled)
		prev = filled.Hash
	}
	// the intact chain verifies against its true anchor
	if bad, err := VerifyFrom(GenesisHash, events); err != nil {
		t.Fatalf("intact chain rejected at %d: %v", bad, err)
	}
	// lop off the first two rows: self-consistent, but no longer rooted
	truncated := events[2:]
	if bad, err := VerifyFrom(GenesisHash, truncated); err == nil {
		t.Fatalf("a truncated head verified as intact (row %d)", bad)
	}
	// ...and rooted at the right anchor it is valid again, which is exactly what
	// archiving does: the retained rows extend the archived segment's terminal hash
	if bad, err := VerifyFrom(events[1].Hash, truncated); err != nil {
		t.Fatalf("correctly anchored continuation rejected at %d: %v", bad, err)
	}
}

/* ------------- P10-09e: the interrupted-archive crash window ------------- */

// memAudit is the slice of the store Archive needs, in memory.
type memAudit struct {
	rows   []Row
	anchor Anchor
	failAt func(step string) error
}

func (m *memAudit) ListAuditEvents(_ context.Context, _ string) ([]Row, error) {
	out := append([]Row(nil), m.rows...)
	return out, nil
}
func (m *memAudit) AuditAnchor(context.Context) (Anchor, error) { return m.anchor, nil }
func (m *memAudit) SetAuditAnchor(_ context.Context, a Anchor) error {
	if m.failAt != nil {
		if err := m.failAt("anchor"); err != nil {
			return err
		}
	}
	m.anchor = a
	return nil
}
func (m *memAudit) DeleteAuditEventsThrough(_ context.Context, seq int64) (int64, error) {
	if m.failAt != nil {
		if err := m.failAt("delete"); err != nil {
			return 0, err
		}
	}
	kept := m.rows[:0]
	n := int64(0)
	for _, r := range m.rows {
		if r.Seq <= seq {
			n++
			continue
		}
		kept = append(kept, r)
	}
	m.rows = kept
	return n, nil
}

func chainOf(t *testing.T, n int) []Row {
	t.Helper()
	prev := GenesisHash
	var rows []Row
	for i := 1; i <= n; i++ {
		e, err := Next(prev, Event{Seq: int64(i), TS: int64(1700000000 + i), ActorKind: "system", Action: "probe"})
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, Row{
			Seq: e.Seq, TS: e.TS, ActorKind: e.ActorKind, Action: e.Action,
			PrevHash: e.PrevHash, Hash: e.Hash,
		})
		prev = e.Hash
	}
	return rows
}

// AC (P10-09e): a crash between "record the anchor" and "delete the archived
// rows" must not look like tampering, and must be repairable.
//
// Archive writes the file, verifies it, records the anchor, and only then
// deletes. Those last two are separate writes and the store exposes no
// transaction, so a process that dies between them leaves an anchor claiming
// history that is still in the table. VerifyChain then measures the live rows
// against the archived terminal hash, they do not link, and an honest chain
// reports as broken — the worst possible answer from a tamper-evidence tool.
func TestInterruptedArchiveIsRepairableNotTampered(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := &memAudit{rows: chainOf(t, 6)}

	// Crash exactly after the anchor is recorded.
	st.failAt = func(step string) error {
		if step == "delete" {
			return errors.New("process died")
		}
		return nil
	}
	if _, err := Archive(ctx, st, dir, 3, nil); err == nil {
		t.Fatal("the injected crash did not surface")
	}
	st.failAt = nil

	// The state on disk: anchor through seq 3, rows 1..6 still present.
	if st.anchor.ArchivedThroughSeq != 3 || len(st.rows) != 6 {
		t.Fatalf("not the crash state: anchor=%d rows=%d", st.anchor.ArchivedThroughSeq, len(st.rows))
	}

	// This must be reported as interrupted, NOT as a broken chain.
	if _, err := VerifyChain(ctx, st); err == nil || !errors.Is(err, ErrArchiveInterrupted) {
		t.Fatalf("an interrupted archive was not distinguished from tampering: %v", err)
	}

	// And it must be repairable, because the archive file was verified before
	// the anchor was ever written: rows through seq 3 are provably preserved.
	n, err := Repair(ctx, st)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if n != 3 {
		t.Fatalf("repair removed %d rows, want 3", n)
	}
	if _, err := VerifyChain(ctx, st); err != nil {
		t.Fatalf("chain still not verifying after repair: %v", err)
	}

	// Repair on a healthy chain is a no-op.
	if n, err := Repair(ctx, st); err != nil || n != 0 {
		t.Fatalf("repair touched a healthy chain: %d %v", n, err)
	}
}

// AC (P10-09e): repair refuses when the archive file is gone — the rows in the
// table are then the only copy, and deleting them would destroy history.
func TestRepairRefusesWithoutItsArchiveFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := &memAudit{rows: chainOf(t, 6)}
	st.failAt = func(step string) error {
		if step == "delete" {
			return errors.New("process died")
		}
		return nil
	}
	if _, err := Archive(ctx, st, dir, 3, nil); err == nil {
		t.Fatal("the injected crash did not surface")
	}
	st.failAt = nil
	if err := os.Remove(st.anchor.ArchivePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Repair(ctx, st); err == nil {
		t.Fatal("repair deleted rows whose archive no longer exists")
	}
	if len(st.rows) != 6 {
		t.Fatalf("rows destroyed with no archive to hold them: %d", len(st.rows))
	}
}

// AC (P12-14): repair must not accept an archive on the strength of one string.
//
// verifyArchiveFile recomputes the whole chain, but when it fails Repair fell
// back to archiveEndsAt, which compared only the LAST line's `hash` field to the
// anchored terminal hash — a value the file itself supplies. Nothing was
// recomputed, so an archive with any number of rewritten rows passed as long as
// its final line still carried the right string, and Repair then deleted those
// rows from the table: the authentic copy destroyed on the word of the forgery.
//
// The fallback exists because a segment may be a continuation rather than rooted
// at genesis, so it cannot anchor at GenesisHash. It can still require the
// segment to be internally consistent, which is what makes the rows provably
// held.
func TestRepairRefusesAnArchiveWhoseRowsWereRewritten(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := &memAudit{rows: chainOf(t, 6)}
	st.failAt = func(step string) error {
		if step == "delete" {
			return errors.New("process died")
		}
		return nil
	}
	if _, err := Archive(ctx, st, dir, 3, nil); err == nil {
		t.Fatal("the injected crash did not surface")
	}
	st.failAt = nil

	// Rewrite an interior row's payload, leaving every `hash` field — including
	// the last line's — exactly as written.
	raw, err := os.ReadFile(st.anchor.ArchivePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("archive has %d lines, need at least 2 to tamper an interior one", len(lines))
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatal(err)
	}
	row["action"] = "something_that_never_happened"
	edited, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(edited)
	if err := os.WriteFile(st.anchor.ArchivePath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Repair(ctx, st); err == nil {
		t.Fatal("repair deleted rows on the strength of a rewritten archive's last line")
	}
	if len(st.rows) != 6 {
		t.Fatalf("%d rows survive; repair destroyed the only authentic copy", len(st.rows))
	}
}
