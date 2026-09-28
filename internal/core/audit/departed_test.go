package audit_test

// The trail of an identity that left (SPEC §3.11, §11.6), on both engines: SQLite always, Postgres
// when the pre-push hook provides one. Every test writes its rows through the node's own audit sink
// (auditsink.SystemChecked), so the rows carry the account id the way a running node writes them.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "modernc.org/sqlite"

	"github.com/pact-cloud/pact-gateway/internal/core/audit"
	"github.com/pact-cloud/pact-gateway/internal/core/auditstore"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/services/auditsink"
)

type engine struct {
	name string
	// open returns a migrated store and a way to run a raw statement against the same database
	// (a test may: CLAUDE.md standing rule 1), for what the store has no method to do.
	open func(t *testing.T) (store.Store, func(stmt string, args ...any) error)
}

var pgSeq int

func engines(t *testing.T) []engine {
	out := []engine{{"sqlite", func(t *testing.T) (store.Store, func(string, ...any) error) {
		path := filepath.Join(t.TempDir(), "pact.db")
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return st, func(stmt string, args ...any) error {
			_, err := db.Exec(stmt, args...)
			return err
		}
	}}}
	if dsn := os.Getenv("PACT_TEST_POSTGRES_DSN"); dsn != "" {
		out = append(out, engine{"postgres", func(t *testing.T) (store.Store, func(string, ...any) error) {
			ctx := context.Background()
			pgSeq++
			name := fmt.Sprintf("pact_archive_%d_%d", os.Getpid(), pgSeq)
			admin, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name)
			if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
				t.Fatal(err)
			}
			admin.Close(ctx)
			i := strings.LastIndex(dsn, "/")
			rest, query := dsn[i+1:], ""
			if j := strings.Index(rest, "?"); j >= 0 {
				query = rest[j:]
			}
			db := dsn[:i+1] + name + query
			st, err := store.OpenPostgres(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := pgx.Connect(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close(ctx) })
			return st, func(stmt string, args ...any) error {
				n := 0
				stmt = regexpQ(stmt, &n)
				_, err := conn.Exec(ctx, stmt, args...)
				return err
			}
		}})
	}
	return out
}

// regexpQ turns `?` placeholders into `$n`.
func regexpQ(s string, n *int) string {
	var b strings.Builder
	for _, r := range s {
		if r == '?' {
			*n++
			fmt.Fprintf(&b, "$%d", *n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// node is a store with the node's one audit writer on it, and the archive job.
type node struct {
	t    *testing.T
	st   store.Store
	raw  func(string, ...any) error
	sink func(action, resource, outcome string) error
	dir  string
	job  *audit.Departed
}

const period = 90 * 24 * time.Hour

func newNode(t *testing.T, e engine) *node {
	st, raw := e.open(t)
	n := &node{t: t, st: st, raw: raw, dir: filepath.Join(t.TempDir(), "audit-archive")}
	n.sink = auditsink.New(context.Background(), st, io.Discard).SystemChecked()
	n.job = &audit.Departed{Store: auditstore.Adapter{St: st}, Dir: n.dir, After: period, Append: n.sink}
	return n
}

func (n *node) write(action, resource, outcome string) {
	n.t.Helper()
	if err := n.sink(action, resource, outcome); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) account(slug string) store.Account {
	n.t.Helper()
	a, err := n.st.CreateAccount(context.Background(), store.CreateAccountParams{Slug: slug, DisplayName: slug, Algo: "p256"})
	if err != nil {
		n.t.Fatal(err)
	}
	return a
}

// leave erases the account and writes the row `account leave` writes when the erase went through.
func (n *node) leave(a store.Account) {
	n.t.Helper()
	if _, err := n.st.DeleteAccount(context.Background(), a.ID); err != nil {
		n.t.Fatal(err)
	}
	n.write("account_leave", "account:"+a.ID+" slug:"+a.Slug+" leaves:1 reserved:1 media:0", "ok")
}

// activity is a few rows naming the identity, the way the surfaces write them, and one row of the
// node's own between each.
func (n *node) activity(a store.Account, peer string) {
	n.write("contact_add", "account:"+a.ID+" contact:"+peer, "ok")
	n.write("listener_start", "public", "ok")
	n.write("send_message", "account:"+a.ID+" contact:"+peer+" msg:m1", "ok")
	n.write("portal_login", "", "ok")
}

func (n *node) live() []audit.Event {
	n.t.Helper()
	rows, err := n.st.ListAuditEvents(context.Background(), "")
	if err != nil {
		n.t.Fatal(err)
	}
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.Event{Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash})
	}
	return out
}

func (n *node) archived() []audit.Event {
	n.t.Helper()
	ev, err := audit.ReadArchives(n.dir)
	if err != nil {
		n.t.Fatal(err)
	}
	return ev
}

// verify is `audit verify`'s two walks: the live rows against the anchor with the archived rows
// put back, and the whole chain from genesis.
func (n *node) verify() error {
	ctx := context.Background()
	as := auditstore.Adapter{St: n.st}
	if _, err := audit.VerifyChain(ctx, as, n.archived()); err != nil {
		return err
	}
	_, err := audit.VerifyWithArchives(ctx, as, nil, n.archived())
	return err
}

// whole says every seq from 1 to the tail is held exactly once across the table and the files,
// and that the chain verifies.
func (n *node) whole() {
	n.t.Helper()
	count := map[int64]int{}
	var tail int64
	for _, e := range append(n.live(), n.archived()...) {
		count[e.Seq]++
		tail = max(tail, e.Seq)
	}
	for s := int64(1); s <= tail; s++ {
		if count[s] != 1 {
			n.t.Fatalf("seq %d is held %d time(s) across the table and the archives", s, count[s])
		}
	}
	if err := n.verify(); err != nil {
		n.t.Fatalf("the chain does not verify: %v", err)
	}
}

func (n *node) at(ts int64) { n.job.Now = func() time.Time { return time.Unix(ts, 0) } }

func (n *node) run() []audit.Segment {
	n.t.Helper()
	segs, err := n.job.Run(context.Background())
	if err != nil {
		n.t.Fatal(err)
	}
	return segs
}

func leaveTS(t *testing.T, rows []audit.Event, id string) int64 {
	for _, e := range rows {
		if e.Action == "account_leave" && e.AccountID == id && e.Outcome == "ok" {
			return e.TS
		}
	}
	t.Fatalf("no account_leave row for %s", id)
	return 0
}

func naming(rows []audit.Event, id string) []audit.Event {
	var out []audit.Event
	for _, e := range rows {
		if audit.Names(e, id) {
			out = append(out, e)
		}
	}
	return out
}

func archiveRows(t *testing.T, rows []audit.Event, action string) []audit.Event {
	var out []audit.Event
	for _, e := range rows {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// The rows naming an identity that left stay in the live trail until the period is over — a
// second before, nothing moves — and then every one of them moves, and nothing else: not the rows
// of an identity still here, not the rows of one whose leave was refused, not the rows of one a
// leave row names but which is still on the node, not the node's own.
func TestTheTrailOfAnIdentityThatLeftMovesOnlyAfterItsPeriod(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			alice, bob, carol, dave := n.account("alice"), n.account("bob"), n.account("carol"), n.account("dave")
			// A row as the node wrote it before its sink filled the account column: the id is in
			// the resource only. Written before the node's writer has loaded the tail, as an older
			// node's row is.
			older := &audit.Writer{Sink: n.st}
			if err := older.Append(context.Background(), "", "owner", "", "contact_add", "account:"+alice.ID+" contact:sha256:old", "ok", "", ""); err != nil {
				t.Fatal(err)
			}
			// And the other way round: the column names her and the resource does not.
			if err := older.Append(context.Background(), alice.ID, "system", "", "contact_refresh", "contact:sha256:old", "unreachable", "", ""); err != nil {
				t.Fatal(err)
			}
			n.activity(alice, "sha256:peer-a")
			n.activity(bob, "sha256:peer-b")
			n.activity(carol, "sha256:peer-c")
			n.activity(dave, "sha256:peer-d")
			// carol's leave was refused: she is still here, and so is her trail.
			n.write("account_leave", "account:"+carol.ID+" slug:carol reason:current_endpoint", "refused")
			// dave has a leave row that says it went through, and his account is here: whatever
			// wrote that row, he has not left, and his trail is his.
			n.write("account_leave", "account:"+dave.ID+" slug:dave leaves:0 reserved:0 media:0", "ok")
			n.leave(alice)
			n.activity(bob, "sha256:peer-b")
			before := n.live()
			left := leaveTS(t, before, alice.ID)
			aliceRows := naming(before, alice.ID)
			if len(aliceRows) != 5 || aliceRows[0].AccountID != "" || strings.Contains(aliceRows[1].Resource, alice.ID) {
				t.Fatalf("seeded %d rows naming alice (%+v), want 5: one by its resource alone, one by its column alone", len(aliceRows), aliceRows)
			}

			n.at(left + int64(period/time.Second) - 1)
			if segs := n.run(); len(segs) != 0 {
				t.Fatalf("a second before the period, the sweep moved %+v", segs)
			}
			if got := n.live(); len(got) != len(before) {
				t.Fatalf("a second before the period the trail went from %d rows to %d", len(before), len(got))
			}
			if files, _ := audit.ArchiveFiles(n.dir); len(files) != 0 {
				t.Fatalf("a second before the period, archives were written: %v", files)
			}

			n.at(left + int64(period/time.Second))
			segs := n.run()
			if len(segs) != 1 || segs[0].AccountID != alice.ID || segs[0].Rows != len(aliceRows) {
				t.Fatalf("at the period the sweep moved %+v, want alice's %d rows", segs, len(aliceRows))
			}
			after := n.live()
			if got := naming(after, alice.ID); len(got) != 0 {
				t.Fatalf("the live trail still names alice: %+v", got)
			}
			for _, id := range []string{bob.ID, carol.ID, dave.ID} {
				if a, b := len(naming(after, id)), len(naming(before, id)); a != b || a == 0 {
					t.Fatalf("an identity still here has %d of its %d rows", a, b)
				}
			}
			if len(after) != len(before)-len(aliceRows)+1 {
				t.Fatalf("the trail went from %d to %d rows; want alice's %d gone and one audit_archive row", len(before), len(after), len(aliceRows))
			}
			// The file holds exactly her rows, as they were, and only its owner can read it.
			held := n.archived()
			if len(held) != len(aliceRows) {
				t.Fatalf("the archive holds %d rows, want %d", len(held), len(aliceRows))
			}
			for i := range held {
				if held[i] != aliceRows[i] {
					t.Fatalf("archived row %d is not the row that was live: %+v vs %+v", i, held[i], aliceRows[i])
				}
			}
			fi, err := os.Stat(segs[0].Path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("the archive is mode %v, want 0600", fi.Mode().Perm())
			}
			want := fmt.Sprintf("%s-%020d-%020d.jsonl", alice.ID, aliceRows[0].Seq, aliceRows[len(aliceRows)-1].Seq)
			if filepath.Base(segs[0].Path) != want {
				t.Fatalf("the archive is %s, want %s", filepath.Base(segs[0].Path), want)
			}
			n.whole()
		})
	}
}

// One audit_archive row per segment, naming the segment and its hashes and not the identity; a
// second sweep finds nothing to move and writes nothing.
func TestOneAuditArchiveRowPerSegment(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			alice, bob := n.account("alice"), n.account("bob")
			n.activity(alice, "sha256:peer-a")
			n.activity(bob, "sha256:peer-b")
			n.leave(alice)
			n.leave(bob)
			n.at(time.Now().Add(period + time.Minute).Unix())
			segs := n.run()
			if len(segs) != 2 {
				t.Fatalf("moved %d segments, want alice's and bob's", len(segs))
			}
			rows := archiveRows(t, n.live(), audit.ArchiveAction)
			if len(rows) != 2 {
				t.Fatalf("%d audit_archive rows for 2 segments", len(rows))
			}
			for i, r := range rows {
				s := segs[i]
				want := fmt.Sprintf("segment:%d-%d rows:%d before:%s after:%s", s.From, s.To, s.Rows, s.Before, s.After)
				if r.Resource != want || r.Outcome != "ok" || r.ActorKind != "system" {
					t.Fatalf("audit_archive row %+v, want resource %q", r, want)
				}
				if r.AccountID != "" || audit.Names(r, alice.ID) || audit.Names(r, bob.ID) {
					t.Fatalf("the audit_archive row names an identity that left: %+v", r)
				}
			}
			if segs := n.run(); len(segs) != 0 {
				t.Fatalf("a second sweep moved %+v", segs)
			}
			if rows := archiveRows(t, n.live(), audit.ArchiveAction); len(rows) != 2 {
				t.Fatalf("a second sweep wrote audit_archive rows: %d", len(rows))
			}
			n.whole()
		})
	}
}

// An archive that was edited, cut short, lost, or contradicts the table is a broken chain; the
// archive as written is not. (The order of a file's lines is not part of the chain: every row's
// seq is in its hash, and verification puts each row in its place by seq.)
func TestATamperedArchiveIsDetected(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			alice := n.account("alice")
			n.activity(alice, "sha256:peer-a")
			n.activity(alice, "sha256:peer-a2")
			n.leave(alice)
			n.write("listener_start", "public", "ok")
			n.at(time.Now().Add(period + time.Minute).Unix())
			segs := n.run()
			if len(segs) != 1 {
				t.Fatalf("segments %+v", segs)
			}
			path := segs[0].Path
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.verify(); err != nil {
				t.Fatalf("the archive as written does not verify: %v", err)
			}
			lines := strings.SplitAfter(strings.TrimSuffix(string(raw), "\n"), "\n")
			tampered := map[string]string{
				"an edited row":   strings.Replace(string(raw), "msg:m1", "msg:m9", 1),
				"a row removed":   strings.Join(append(append([]string{}, lines[:1]...), lines[2:]...), ""),
				"an emptied file": "",
			}
			for what, body := range tampered {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := n.verify(); err == nil {
					t.Errorf("%s verified as intact", what)
				}
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := n.verify(); err == nil {
				t.Error("a lost archive verified as intact")
			}
			// A copy of a live row with different content, in a file of its own.
			live := n.live()
			forged := live[0]
			forged.Outcome = "refused"
			var b strings.Builder
			if err := audit.ExportJSONL(&b, []audit.Event{forged}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(n.dir, "x-1-1.jsonl"), []byte(b.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := n.verify(); err == nil {
				t.Error("a file contradicting a live row verified as intact")
			}
			if err := os.Remove(filepath.Join(n.dir, "x-1-1.jsonl")); err != nil {
				t.Fatal(err)
			}
			n.whole() // the control: restored, it verifies
		})
	}
}

// failing wraps the store the job sees, to stop a run at a chosen step as a crash would.
type failing struct {
	auditstore.Adapter
	archiveRows func(rows []audit.Row) ([]audit.Row, error)
}

func (f failing) ArchiveRows(ctx context.Context, rows []audit.Row) (int64, error) {
	if f.archiveRows != nil {
		named, err := f.archiveRows(rows)
		if err != nil {
			return 0, err
		}
		rows = named
	}
	return f.Adapter.ArchiveRows(ctx, rows)
}

// A run that stops at any step — after the file is written, after its audit_archive row is
// appended, or inside the transaction that removes the rows — leaves every row exactly once
// across the table and the files, and the next run finishes it with one audit_archive row.
func TestACrashMidArchiveLosesAndDuplicatesNothing(t *testing.T) {
	died := errors.New("the process died")
	for _, e := range engines(t) {
		for _, step := range []string{"after the file", "after the audit row", "inside the transaction", "a temporary file"} {
			t.Run(e.name+"/"+step, func(t *testing.T) {
				n := newNode(t, e)
				alice, bob := n.account("alice"), n.account("bob")
				n.activity(alice, "sha256:peer-a")
				n.activity(bob, "sha256:peer-b")
				n.leave(alice)
				aliceRows := naming(n.live(), alice.ID)
				n.at(time.Now().Add(period + time.Minute).Unix())
				job := *n.job
				switch step {
				case "after the file":
					job.Append = func(string, string, string) error { return died }
				case "after the audit row":
					job.Store = failing{Adapter: auditstore.Adapter{St: n.st}, archiveRows: func([]audit.Row) ([]audit.Row, error) { return nil, died }}
				case "inside the transaction":
					// The transaction deletes alice's rows and then meets a row whose hash is not
					// the one it was named with: it must take none of them.
					bobs := naming(n.live(), bob.ID)
					job.Store = failing{Adapter: auditstore.Adapter{St: n.st}, archiveRows: func(rows []audit.Row) ([]audit.Row, error) {
						return append(rows, audit.Row{Seq: bobs[0].Seq, Hash: strings.Repeat("0", 64)}), nil
					}}
				case "a temporary file":
					if err := os.MkdirAll(n.dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(n.dir, ".half-written.tmp"), []byte(`{"seq":`), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if step != "a temporary file" {
					if _, err := job.Run(context.Background()); err == nil {
						t.Fatal("the injected crash did not surface")
					}
					if got := naming(n.live(), alice.ID); len(got) != len(aliceRows) {
						t.Fatalf("after the crash the table holds %d of alice's %d rows", len(got), len(aliceRows))
					}
					if len(naming(n.live(), bob.ID)) == 0 {
						t.Fatal("the crash took bob's rows")
					}
					// Every row is still live; the file, if written, holds copies. Verify says so
					// and is not fooled into calling the chain broken.
					if err := n.verify(); err != nil {
						t.Fatalf("an unfinished run reads as a broken chain: %v", err)
					}
				}
				n.run()
				if got := naming(n.live(), alice.ID); len(got) != 0 {
					t.Fatalf("the resumed run left %d of alice's rows live", len(got))
				}
				if got := archiveRows(t, n.live(), audit.ArchiveAction); len(got) != 1 {
					t.Fatalf("%d audit_archive rows after a resumed run, want 1", len(got))
				}
				if got := n.archived(); len(got) != len(aliceRows) {
					t.Fatalf("the archives hold %d rows, want alice's %d", len(got), len(aliceRows))
				}
				if files, _ := os.ReadDir(n.dir); len(files) != 1 {
					t.Fatalf("the archive directory holds %d entries, want the one archive", len(files))
				}
				n.whole()
			})
		}
	}
}

// The prune guard still refuses every delete but the two sanctioned ones: a row the head anchor
// covers, and a row listed with its hash inside Store.ArchiveAuditRows' transaction — which lists
// nothing once it has committed.
func TestTheTriggerStillRefusesAnyOtherDeletion(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			ctx := context.Background()
			alice := n.account("alice")
			n.activity(alice, "sha256:peer-a")
			rows := n.live()
			if err := n.raw("DELETE FROM audit_events WHERE seq = ?", rows[1].Seq); err == nil {
				t.Error("a plain DELETE of one row went through")
			}
			if err := n.raw("UPDATE audit_events SET outcome = 'x' WHERE seq = ?", rows[1].Seq); err == nil {
				t.Error("an UPDATE went through")
			}
			if _, err := n.st.DeleteAuditEventsThrough(ctx, rows[1].Seq); err == nil {
				t.Error("a head prune with no anchor went through")
			}
			// Named with a hash that is not the row's: refused, and nothing goes.
			if _, err := n.st.ArchiveAuditRows(ctx, []store.AuditArchiveRow{{Seq: rows[0].Seq, Hash: rows[0].Hash}, {Seq: rows[1].Seq, Hash: rows[0].Hash}}); err == nil {
				t.Error("a row named with another row's hash was archived")
			}
			// Named with a seq that is not in the chain: refused, and nothing goes.
			if _, err := n.st.ArchiveAuditRows(ctx, []store.AuditArchiveRow{{Seq: rows[0].Seq, Hash: rows[0].Hash}, {Seq: 999999, Hash: rows[0].Hash}}); err == nil {
				t.Error("an archive of a row the chain does not hold went through")
			}
			if got := n.live(); len(got) != len(rows) {
				t.Fatalf("refused archives removed rows: %d of %d left", len(got), len(rows))
			}
			// The control: the sanctioned path removes exactly the rows it names ...
			if k, err := n.st.ArchiveAuditRows(ctx, []store.AuditArchiveRow{{Seq: rows[1].Seq, Hash: rows[1].Hash}}); err != nil || k != 1 {
				t.Fatalf("the sanctioned archive of one row: %d %v", k, err)
			}
			// ... and leaves nothing listed: the seq it listed can be listed again (the key would
			// refuse it otherwise), and the row after it is refused a plain DELETE.
			if err := n.raw("INSERT INTO audit_archive_rows (seq, hash) VALUES (?, ?)", rows[1].Seq, "x"); err != nil {
				t.Errorf("the archive left its list behind: %v", err)
			}
			if err := n.raw("DELETE FROM audit_events WHERE seq = ?", rows[2].Seq); err == nil {
				t.Error("after an archive, a plain DELETE went through")
			}
			if err := n.raw("INSERT INTO audit_archive_rows (seq, hash) VALUES (?, ?)", rows[3].Seq, "not-its-hash"); err != nil {
				t.Fatal(err)
			}
			if err := n.raw("DELETE FROM audit_events WHERE seq = ?", rows[3].Seq); err == nil {
				t.Error("a row listed with the wrong hash was deleted")
			}
		})
	}
}

// The rows about to go are never the chain's tail: a writer that starts afresh (a restart) reads
// its next seq from the tail, and a moved tail would give the next row the seq of an archived one.
// The run that is stopped before its audit_archive row is written, and the node restarted, is the
// case: had the rows gone first, the tail would be gone with them.
func TestAWriterAfterAnArchiveExtendsTheChain(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			alice := n.account("alice")
			n.activity(alice, "sha256:peer-a")
			n.leave(alice) // the leave row is the tail
			n.at(time.Now().Add(period + time.Minute).Unix())
			stopped := *n.job
			stopped.Append = func(string, string, string) error { return errors.New("the process died") }
			if _, err := stopped.Run(context.Background()); err == nil {
				t.Fatal("the injected crash did not surface")
			}
			// The node restarts: one new writer, which reads its next seq from the tail.
			n.sink = auditsink.New(context.Background(), n.st, io.Discard).SystemChecked()
			n.job.Append = n.sink
			n.write("listener_start", "public", "ok")
			if err := n.verify(); err != nil {
				t.Fatalf("after a restart the chain does not verify: %v", err)
			}
			if segs := n.run(); len(segs) != 1 {
				t.Fatalf("segments %+v", segs)
			}
			var tail int64
			for _, r := range append(n.live(), n.archived()...) {
				tail = max(tail, r.Seq)
			}
			restarted := auditsink.New(context.Background(), n.st, io.Discard).SystemChecked()
			if err := restarted("listener_start", "public", "ok"); err != nil {
				t.Fatal(err)
			}
			live := n.live()
			if got := live[len(live)-1].Seq; got != tail+1 {
				t.Fatalf("the restarted writer wrote seq %d, want %d", got, tail+1)
			}
			n.whole()
		})
	}
}

// The head archive (SPEC §11.6) and an identity's archive, in either order over the same stretch
// of the chain: `audit verify`'s walks and `audit repair` agree the chain is whole.
func TestHeadAndIdentityArchivesVerifyTogether(t *testing.T) {
	for _, e := range engines(t) {
		for _, order := range []string{"identity first", "head first"} {
			t.Run(e.name+"/"+order, func(t *testing.T) {
				n := newNode(t, e)
				ctx := context.Background()
				as := auditstore.Adapter{St: n.st}
				heads := filepath.Join(t.TempDir(), "audit")
				alice, bob := n.account("alice"), n.account("bob")
				n.activity(alice, "sha256:peer-a")
				n.activity(bob, "sha256:peer-b")
				n.leave(alice)
				n.activity(bob, "sha256:peer-b")
				n.at(time.Now().Add(period + time.Minute).Unix())
				through := n.live()[5].Seq
				head := func() {
					if _, err := audit.Archive(ctx, as, heads, through, n.archived(), nil); err != nil {
						t.Fatalf("head archive: %v", err)
					}
				}
				if order == "identity first" {
					n.run()
					head()
				} else {
					head()
					n.run()
				}
				files, _ := filepath.Glob(filepath.Join(heads, "audit-*.jsonl"))
				if _, err := audit.VerifyChain(ctx, as, n.archived()); err != nil {
					t.Fatalf("anchored walk: %v", err)
				}
				if _, err := audit.VerifyWithArchives(ctx, as, files, n.archived()); err != nil {
					t.Fatalf("walk from genesis: %v", err)
				}
				if k, err := audit.Repair(ctx, as, n.archived()); err != nil || k != 0 {
					t.Fatalf("repair on a whole chain: %d %v", k, err)
				}
				if got := naming(n.live(), alice.ID); len(got) != 0 {
					t.Fatalf("alice's rows are still live: %+v", got)
				}
				// What SPEC §3.11 says of the head archive: a row it took before the period ended
				// stays in it; the identity's archive takes only what was still in the table.
				var inHead []audit.Event
				for _, f := range files {
					raw, err := os.Open(f)
					if err != nil {
						t.Fatal(err)
					}
					ev, err := audit.ImportJSONL(raw)
					raw.Close()
					if err != nil {
						t.Fatal(err)
					}
					inHead = append(inHead, naming(ev, alice.ID)...)
				}
				if order == "head first" && len(inHead) == 0 {
					t.Fatal("the head archive took none of alice's rows: this case proves nothing")
				}
				if order == "identity first" && len(inHead) != 0 {
					t.Fatalf("the head archive holds %d of alice's rows after her own archive took them", len(inHead))
				}
			})
		}
	}
}

// When law requires an archive's rows to go, Erase leaves what the chain needs of them — seq,
// prev_hash, hash — and nothing that names the identity: the chain still verifies, and the rows
// are reported as erased. A forged skeleton is still caught by the link it breaks.
func TestAnErasedArchiveStillLinksTheChain(t *testing.T) {
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			n := newNode(t, e)
			alice := n.account("alice")
			n.activity(alice, "sha256:peer-a")
			n.leave(alice)
			n.write("listener_start", "public", "ok")
			n.at(time.Now().Add(period + time.Minute).Unix())
			segs := n.run()
			out, k, err := audit.Erase(segs[0].Path)
			if err != nil || k != segs[0].Rows {
				t.Fatalf("erase: %d %v", k, err)
			}
			if _, err := os.Stat(segs[0].Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the archive that named alice is still there: %v", err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), alice.ID) || strings.Contains(out, alice.ID) || strings.Contains(string(raw), "peer-a") {
				t.Fatalf("the erased archive still names the identity: %s %s", out, raw)
			}
			erased := 0
			for _, e := range n.archived() {
				if e.Erased {
					erased++
				}
			}
			if erased != segs[0].Rows {
				t.Fatalf("%d rows reported erased, want %d", erased, segs[0].Rows)
			}
			n.whole()
			// A skeleton whose hash was changed no longer links to the row after it.
			first := n.archived()[0]
			if err := os.WriteFile(out, []byte(strings.Replace(string(raw), first.Hash, strings.Repeat("a", 64), 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := n.verify(); err == nil {
				t.Fatal("a forged skeleton verified")
			}
		})
	}
}
