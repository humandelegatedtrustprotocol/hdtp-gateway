package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The wipe migration 0005 schedules (SEP-0006): on each engine, every conversation stored under a
// thread id of neither form goes, with its messages, its change rows, its read marker (the thread
// row's) and the files only it names, including a file whose record is older than migration 0003,
// which the orphan sweep would keep; and so do the messages and change rows of such an id that no
// thread row names. Every thread of a form stays as it was, with its messages, change rows and
// read marker, as do a file a kept thread also names and every change row whose thread_id is empty,
// which names no thread. The wipe runs once: the second run finds it done.
func TestTheWipeDeletesEveryConversationOfNeitherFormAndOnlyThose(t *testing.T) {
	for engine, stores := range sharedStores(t, 1) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			st := stores[0]
			blobs := BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}
			svc := &Service{Store: st, Blobs: blobs}
			a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
			if err != nil {
				t.Fatal(err)
			}
			const peer = "sha256:peer"
			seq := 0
			message := func(threadID, body, kind string) store.Message {
				t.Helper()
				seq++
				m := store.Message{ID: fmt.Sprintf("row-%d", seq), AccountID: a.ID, ContactFpr: peer, MsgID: fmt.Sprintf("msg-%d", seq), ThreadID: threadID,
					Direction: "in", Sender: "agent", Body: body, Kind: kind, Status: "delivered", CreatedAt: 1}
				if err := st.InsertMessage(ctx, m); err != nil {
					t.Fatalf("%q: %v", threadID, err)
				}
				return m
			}
			file := func(data string) string {
				t.Helper()
				hash, err := blobs.Put([]byte(data))
				if err != nil {
					t.Fatal(err)
				}
				// Dated before migration 0003: the orphan sweep keeps such a record whatever names it.
				if err := st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: hash, Size: int64(len(data)), Mime: "text/plain", CreatedAt: 1}); err != nil {
					t.Fatal(err)
				}
				return hash
			}
			mediaBody := func(hash string) string {
				b, _ := json.Marshal(MediaMeta{Filename: "f.txt", Mime: "text/plain", Hash: hash})
				return string(b)
			}
			conversation := func(threadID string) {
				t.Helper()
				if err := st.InsertThread(ctx, store.Thread{ID: threadID, AccountID: a.ID, ContactFpr: peer, CreatedAt: 1, LastAt: 1}); err != nil {
					t.Fatalf("%q: %v", threadID, err)
				}
				message(threadID, "hello", "text")
				message(threadID, "unread", "text")
				if _, err := st.AppendChange(ctx, store.Change{AccountID: a.ID, Kind: "message", ThreadID: threadID, ContactFpr: peer, At: 1}); err != nil {
					t.Fatal(err)
				}
			}

			ids := testid.ThreadIDs()
			if engine == "sqlite" {
				// SQLite stores a NUL; a reader that stops at it sees "ab" and keeps the thread.
				ids = append(ids, testid.ThreadIDCase{Name: "NUL", ID: "ab\x00!!", Code: "bad_request"})
			}
			var wiped, kept []string
			for _, c := range ids {
				conversation(c.ID)
				if c.Code == "" {
					kept = append(kept, c.ID)
				} else {
					wiped = append(wiped, c.ID)
				}
			}
			// The read marker of each kept thread, through its first message.
			for _, id := range kept {
				msgs, _ := st.ListMessagesByThread(ctx, a.ID, id)
				if _, err := st.MarkThreadReadThrough(ctx, a.ID, id, msgs[0].Seq); err != nil {
					t.Fatal(err)
				}
			}
			onlyWiped := file("named only by a thread of neither form")
			shared := file("named by both")
			message("my-thread", mediaBody(onlyWiped), "media")
			message("my-thread", mediaBody(shared), "media")
			message("abc", mediaBody(shared), "media")
			// Of neither form and no thread row: a message, and a change row.
			message("no.thread.row", "orphan", "text")
			if _, err := st.AppendChange(ctx, store.Change{AccountID: a.ID, Kind: "message", ThreadID: "a b c", At: 1}); err != nil {
				t.Fatal(err)
			}
			// A contact's change row names no thread.
			if _, err := st.AppendChange(ctx, store.Change{AccountID: a.ID, Kind: "contact", ContactFpr: peer, At: 1}); err != nil {
				t.Fatal(err)
			}

			got, err := svc.WipeThreadIDs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Every case of neither form had a thread and two messages; my-thread two more and one file.
			want := Wiped{AccountID: a.ID, Threads: int64(len(wiped)), Messages: int64(2*len(wiped) + 2 + 1), Files: 1}
			if len(got) != 1 || got[0] != want {
				t.Fatalf("wiped %+v, want [%+v]", got, want)
			}
			for _, id := range append(wiped, "no.thread.row") {
				if _, err := st.GetThread(ctx, a.ID, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("%q: the thread is still there: %v", id, err)
				}
				if msgs, _ := st.ListMessagesByThread(ctx, a.ID, id); len(msgs) != 0 {
					t.Fatalf("%q: %d messages left", id, len(msgs))
				}
			}
			for _, id := range kept {
				if _, err := st.GetThread(ctx, a.ID, id); err != nil {
					t.Fatalf("%q: a thread of a form went: %v", id, err)
				}
				if msgs, _ := st.ListMessagesByThread(ctx, a.ID, id); len(msgs) < 2 {
					t.Fatalf("%q: its messages went: %d left", id, len(msgs))
				}
				if n, _ := st.UnreadCount(ctx, a.ID, id); n != 1 {
					t.Fatalf("%q: read marker moved: %d unread, want 1", id, n)
				}
			}
			changes, err := st.AccountChangesAfter(ctx, a.ID, 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			left := map[string]int{}
			for _, c := range changes {
				left[c.ThreadID]++
			}
			// Two rows name no thread: the contact's, and the one written for the thread whose id was
			// empty, which reads as the contact's does.
			if len(changes) != len(kept)+2 || left[""] != 2 {
				t.Fatalf("change rows left %v, want one per kept thread and the two that name none", left)
			}
			for _, id := range kept {
				if left[id] != 1 {
					t.Fatalf("%q: its change row went", id)
				}
			}
			if _, err := blobs.Get(onlyWiped); err == nil {
				t.Fatal("the file only a wiped thread named is still on disk")
			}
			if _, err := st.GetBlob(ctx, a.ID, onlyWiped); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("its record is still there: %v", err)
			}
			if _, err := blobs.Get(shared); err != nil {
				t.Fatalf("a file a kept thread names went: %v", err)
			}

			if pending, err := st.ThreadIDWipePending(ctx); err != nil || pending {
				t.Fatalf("still scheduled after it ran: %v %v", pending, err)
			}
			// Scheduled no more, it does nothing: a thread of neither form written now stays.
			if err := st.InsertThread(ctx, store.Thread{ID: "after-the-wipe", AccountID: a.ID, ContactFpr: peer, CreatedAt: 2, LastAt: 2}); err != nil {
				t.Fatal(err)
			}
			if again, err := svc.WipeThreadIDs(ctx); err != nil || len(again) != 0 {
				t.Fatalf("the second run: %+v %v", again, err)
			}
			if _, err := st.GetThread(ctx, a.ID, "after-the-wipe"); err != nil {
				t.Fatalf("the second run wiped: %v", err)
			}
		})
	}
}
