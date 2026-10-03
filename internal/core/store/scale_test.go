package store

// The store at the size a node grows to: 10,000 contacts, a million messages in 50,000 threads, a
// million audit rows, a million idempotency records and 100,000 media rows, across four accounts
// of which one is heavy. Every number the round-2 plan quotes for the database comes from here.
//
// Seeding takes a minute, so it happens once, into the file HDTP_SCALE_DB names, and every
// benchmark opens that file. Nothing here runs unless the variable is set:
//
//	HDTP_SCALE_DB=/path/scale.db go test ./internal/core/store/ -run '^$' -bench '^BenchmarkScale' -benchtime 20x
//
// The rows are written with plain SQL in one transaction because going through the Store a row at
// a time would measure a million commits. What is MEASURED goes through the Store, so it is what
// the node does.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
)

const (
	scaleAccounts    = 4
	scaleContacts    = 10_000
	scaleThreads     = 50_000
	scaleMessages    = 1_000_000
	scaleAudit       = 1_000_000
	scaleIdempotency = 1_000_000
	scaleBlobs       = 100_000
	scalePendingOut  = 200
	scaleMediaEvery  = 100
	scaleRareActor   = "owner:rare"
	scaleRareEvery   = 33_333
	scaleRareRows    = (scaleAudit-1-7)/scaleRareEvery + 1 // the rows i with i % scaleRareEvery == 7
	scaleNow         = int64(1_790_000_000)
)

// scaleAccount spreads rows so that account 0 holds seven tenths of everything.
func scaleAccount(i int) int {
	if i%10 < 7 {
		return 0
	}
	return 1 + i%(scaleAccounts-1)
}

func scaleAccountID(n int) string { return fmt.Sprintf("acct-%d", n) }
func scaleFpr(i int) string       { return fmt.Sprintf("sha256:contact-%06d", i) }

func openScale(tb testing.TB) *SQLite {
	tb.Helper()
	path := os.Getenv("HDTP_SCALE_DB")
	if path == "" {
		tb.Skip("HDTP_SCALE_DB is not set: the at-scale numbers are not measured in an ordinary run")
	}
	st, err := OpenSQLite(path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		tb.Fatal(err)
	}
	// Seeding is one transaction, so a file holds either nothing or everything.
	var n int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages").Scan(&n); err != nil {
		tb.Fatal(err)
	}
	if n == 0 {
		seedScale(tb, st.db)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages").Scan(&n); err != nil || n < scaleMessages {
		tb.Fatalf("%s holds %d messages, not the %d a seeded file has (%v): delete it and run again", path, n, scaleMessages, err)
	}
	return st
}

func seedScale(tb testing.TB, db *sql.DB) {
	tb.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	must := func(err error) {
		if err != nil {
			tb.Fatal(err)
		}
	}
	prep := func(q string) *sql.Stmt {
		s, err := tx.PrepareContext(ctx, q)
		must(err)
		return s
	}
	for a := 0; a < scaleAccounts; a++ {
		_, err := tx.ExecContext(ctx, "INSERT INTO accounts (id, slug, display_name, algo, created_at) VALUES (?, ?, ?, 'ed25519', ?)",
			scaleAccountID(a), fmt.Sprintf("scale-%d", a), fmt.Sprintf("Scale %d", a), scaleNow)
		must(err)
	}
	contacts := prep("INSERT INTO contacts (id, account_id, fingerprint, status, display_name, created_at, endpoint) VALUES (?, ?, ?, 'active', ?, ?, ?)")
	for i := 0; i < scaleContacts; i++ {
		_, err := contacts.ExecContext(ctx, fmt.Sprintf("c-%06d", i), scaleAccountID(scaleAccount(i)), scaleFpr(i), fmt.Sprintf("Contact %d", i),
			scaleNow-int64((i*7919)%1_000_000), fmt.Sprintf("https://peer-%d.example/mcp", i))
		must(err)
	}
	// A thread belongs to the contact of the same index, so a contact's account and its threads' agree.
	threads := prep("INSERT INTO threads (id, account_id, contact_fpr, topic, created_at, last_at) VALUES (?, ?, ?, ?, ?, ?)")
	for i := 0; i < scaleThreads; i++ {
		c := i % scaleContacts
		_, err := threads.ExecContext(ctx, fmt.Sprintf("t-%06d", i), scaleAccountID(scaleAccount(c)), scaleFpr(c), fmt.Sprintf("Topic %d", i),
			scaleNow-2_000_000, scaleNow-int64((i*104729)%2_000_000))
		must(err)
	}
	messages := prep("INSERT INTO messages (id, account_id, contact_fpr, msg_id, thread_id, direction, sender, kind, body, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'agent', ?, ?, ?, ?, ?)")
	text := "The quarterly numbers are attached; the short version is that the pilot held and the second site can start in March."
	for i := 0; i < scaleMessages; i++ {
		t := i % scaleThreads
		c := t % scaleContacts
		direction, status := "in", "delivered"
		if i%2 == 1 {
			direction = "out"
			// The sweep's prey: a couple of hundred pending rows, spread through the table.
			if i%(scaleMessages/scalePendingOut) == 1 {
				status = "pending"
			}
		}
		// One message in a hundred carries media, and names the blob it carries.
		kind, body := "text", text
		if i%scaleMediaEvery == 0 {
			kind, body = "media", fmt.Sprintf(`{"filename":"f-%d.pdf","mime":"application/pdf","hash":"sha256:blob-%06d","size":4096}`, i, (i/scaleMediaEvery)%scaleBlobs)
		}
		_, err := messages.ExecContext(ctx, fmt.Sprintf("m-%07d", i), scaleAccountID(scaleAccount(c)), scaleFpr(c), fmt.Sprintf("msg-%07d", i),
			fmt.Sprintf("t-%06d", t), direction, kind, body, status, scaleNow-int64(scaleMessages-i), scaleNow+86_400)
		must(err)
	}
	audit := prep("INSERT INTO audit_events (ts, account_id, actor_kind, actor_id, action, resource, outcome, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, 'ok', ?, ?)")
	for i := 0; i < scaleAudit; i++ {
		var account any = scaleAccountID(scaleAccount(i))
		kind, actor := "contact", scaleFpr(i%scaleContacts)
		switch {
		case i%scaleRareEvery == 7: // a few dozen rows in a million
			kind, actor = "owner", scaleRareActor
		case i%5 == 0:
			kind, actor, account = "system", "system", nil
		}
		_, err := audit.ExecContext(ctx, scaleNow-int64(scaleAudit-i), account, kind, actor, "send_message", "contact:"+scaleFpr(i%scaleContacts),
			fmt.Sprintf("h-%07d", i), fmt.Sprintf("h-%07d", i+1))
		must(err)
	}
	// Half already past their window, as they would be on a node that has run for a while.
	idem := prep("INSERT INTO idempotency (account_id, contact_fpr, msg_id, ack, created_at, expires_at) VALUES (?, ?, ?, '{}', ?, ?)")
	for i := 0; i < scaleIdempotency; i++ {
		c := i % scaleContacts
		_, err := idem.ExecContext(ctx, scaleAccountID(scaleAccount(c)), scaleFpr(c), fmt.Sprintf("env:msg-%07d", i), scaleNow-int64(scaleIdempotency-i), scaleNow-int64(scaleIdempotency/2-i))
		must(err)
	}
	blobs := prep("INSERT INTO blobs (account_id, hash, size, created_at) VALUES (?, ?, ?, ?)")
	for i := 0; i < scaleBlobs; i++ {
		_, err := blobs.ExecContext(ctx, scaleAccountID(scaleAccount(i)), fmt.Sprintf("sha256:blob-%06d", i), 4096+i%100_000, scaleNow-int64((i*15485863)%2_000_000))
		must(err)
	}
	must(tx.Commit())
}

func benchScale(b *testing.B, fn func(ctx context.Context, st *SQLite, i int) error) {
	b.Helper()
	st := openScale(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fn(ctx, st, i); err != nil {
			b.Fatal(err)
		}
	}
}

// The retry sweep: every tick, the pending outbound rows, oldest first.
func BenchmarkScaleListPendingOutbound(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListPendingOutbound(ctx, 50)
		if err == nil && len(rows) != 50 {
			return fmt.Errorf("the sweep found %d pending rows, not 50", len(rows))
		}
		return err
	})
}

// Retention with nothing old enough to go: the cost of finding that out.
func BenchmarkScaleDeleteMessagesBeforeNothingOld(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		n, err := st.DeleteMessagesBefore(ctx, scaleAccountID(0), scaleNow-10_000_000)
		if err == nil && n != 0 {
			return fmt.Errorf("retention removed %d rows from a store with nothing that old", n)
		}
		return err
	})
}

func BenchmarkScaleDeleteEmptyThreadsNoneEmpty(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		n, err := st.DeleteEmptyThreads(ctx, scaleAccountID(0))
		if err == nil && n != 0 {
			return fmt.Errorf("removed %d threads, and every thread has messages", n)
		}
		return err
	})
}

func BenchmarkScaleCountBlobRefs(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, i int) error {
		n, err := st.CountBlobRefs(ctx, fmt.Sprintf("sha256:blob-%06d", (i*7919)%scaleBlobs))
		if err == nil && n != 1 {
			return fmt.Errorf("a blob has %d references, not 1", n)
		}
		return err
	})
}

func BenchmarkScaleListContacts(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListContacts(ctx, scaleAccountID(0))
		if err == nil && len(rows) != scaleContacts*7/10 {
			return fmt.Errorf("listed %d contacts", len(rows))
		}
		return err
	})
}

func BenchmarkScaleListThreadsByAccount(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListThreadsByAccount(ctx, scaleAccountID(0))
		if err == nil && len(rows) != scaleThreads*7/10 {
			return fmt.Errorf("listed %d threads", len(rows))
		}
		return err
	})
}

// What a retention sweep reads to learn which media is still referenced.
func BenchmarkScaleLiveMedia(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		// Every hundredth message lands on a contact whose index is a multiple of a hundred, and
		// those all belong to account 0: it holds every media message there is.
		bodies, err := st.ListMediaBodies(ctx, scaleAccountID(0))
		if err == nil && len(bodies) != scaleMessages/scaleMediaEvery {
			return fmt.Errorf("%d media messages", len(bodies))
		}
		return err
	})
}

// The trail as the portal reads it: newest first, bounded, optionally narrowed.
func BenchmarkScaleAuditPageEverything(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListAuditEventsPage(ctx, AuditPage{Limit: 100})
		if err == nil && len(rows) != 100 {
			return fmt.Errorf("a page of %d", len(rows))
		}
		return err
	})
}

func BenchmarkScaleAuditPageOneAccount(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListAuditEventsPage(ctx, AuditPage{Account: scaleAccountID(3), Limit: 100})
		if err == nil && len(rows) != 100 {
			return fmt.Errorf("a page of %d", len(rows))
		}
		return err
	})
}

// The bad case for a filter applied while walking the chain backwards: an actor with 31 rows.
func BenchmarkScaleAuditPageRareActor(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListAuditEventsPage(ctx, AuditPage{Actor: scaleRareActor, Limit: 100})
		if err == nil && len(rows) != scaleRareRows {
			return fmt.Errorf("the rare actor has %d rows, not %d", len(rows), scaleRareRows)
		}
		return err
	})
}

func BenchmarkScaleListAuditEventsByRareActor(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, _ int) error {
		rows, err := st.ListAuditEvents(ctx, scaleRareActor)
		if err == nil && len(rows) != scaleRareRows {
			return fmt.Errorf("the rare actor has %d rows, not %d", len(rows), scaleRareRows)
		}
		return err
	})
}

// The floor: lookups that were indexed all along, so a change that slows them shows.
func BenchmarkScaleGetMessageByMsgID(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, i int) error {
		m := (i*7919)%(scaleMessages/2)*2 + 1 // an outbound row
		c := (m % scaleThreads) % scaleContacts
		_, err := st.GetMessageByMsgID(ctx, scaleAccountID(scaleAccount(c)), scaleFpr(c), "out", fmt.Sprintf("msg-%07d", m))
		return err
	})
}

func BenchmarkScaleListMessagesByThread(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, i int) error {
		t := (i * 104729) % scaleThreads
		rows, err := st.ListMessagesByThread(ctx, scaleAccountID(scaleAccount(t%scaleContacts)), fmt.Sprintf("t-%06d", t))
		if err == nil && len(rows) != scaleMessages/scaleThreads {
			return fmt.Errorf("a thread of %d", len(rows))
		}
		return err
	})
}

func BenchmarkScaleGetContact(b *testing.B) {
	benchScale(b, func(ctx context.Context, st *SQLite, i int) error {
		c := (i * 7919) % scaleContacts
		_, err := st.GetContact(ctx, scaleAccountID(scaleAccount(c)), scaleFpr(c))
		return err
	})
}

// The write path of one inbound sealed message: the envelope's idempotency record and the row.
func BenchmarkScaleInboundWrite(b *testing.B) {
	st := openScale(b)
	ctx := context.Background()
	run := newID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := (i * 7919) % scaleContacts
		acct, fpr, id := scaleAccountID(scaleAccount(c)), scaleFpr(c), fmt.Sprintf("bench-%s-%d", run, i)
		if _, _, err := st.PutIdempotency(ctx, acct, fpr, "env:"+id, "{}", scaleNow+300); err != nil {
			b.Fatal(err)
		}
		// Its own thread, so that running this leaves the threads the read benchmarks count as they were.
		if err := st.InsertMessage(ctx, Message{ID: newID(), AccountID: acct, ContactFpr: fpr, MsgID: id, ThreadID: "t-written-by-the-benchmark",
			Direction: "in", Sender: "agent", Kind: "text", Body: "hello", Status: "delivered", CreatedAt: scaleNow}); err != nil {
			b.Fatal(err)
		}
	}
}
