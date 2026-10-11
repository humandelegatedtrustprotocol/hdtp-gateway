package messaging

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// wipeEnv is one SQLite store, migrated (so the wipe is pending), with two accounts.
func wipeEnv(t *testing.T) (store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	st := sharedStores(t, 1)["sqlite"][0]
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "b", DisplayName: "B", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID > b.ID {
		a, b = b, a
	}
	return st, a.ID, b.ID
}

func wipeMessage(t *testing.T, st store.Store, acct, id, threadID string) {
	t.Helper()
	if err := st.InsertMessage(context.Background(), store.Message{ID: id, AccountID: acct, ContactFpr: "sha256:peer", MsgID: id, ThreadID: threadID,
		Direction: "in", Sender: "agent", Body: "hi", Kind: "text", Status: "delivered", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
}

// A message row whose thread_id is empty, with no thread row (an import could write one), is of
// neither form and goes with the wipe; a change row whose thread_id is empty names no thread and
// stays.
func TestTheWipeDeletesAMessageWithAnEmptyThreadID(t *testing.T) {
	st, acct, _ := wipeEnv(t)
	ctx := context.Background()
	wipeMessage(t, st, acct, "m1", "")
	wipeMessage(t, st, acct, "m2", "kept")
	if _, err := st.AppendChange(ctx, store.Change{AccountID: acct, Kind: "contact", ContactFpr: "sha256:peer", At: 1}); err != nil {
		t.Fatal(err)
	}
	var got []Wiped
	if err := (&Service{Store: st}).WipeThreadIDs(ctx, func(w Wiped) { got = append(got, w) }); err != nil {
		t.Fatal(err)
	}
	if want := (Wiped{AccountID: acct, Messages: 1}); len(got) != 1 || got[0] != want {
		t.Fatalf("wiped %+v, want [%+v]", got, want)
	}
	if msgs, _ := st.ListMessagesByThread(ctx, acct, ""); len(msgs) != 0 {
		t.Fatalf("%d messages with an empty thread_id left", len(msgs))
	}
	if msgs, _ := st.ListMessagesByThread(ctx, acct, "kept"); len(msgs) != 1 {
		t.Fatal("the message of a form went")
	}
	if changes, _ := st.AccountChangesAfter(ctx, acct, 0, 10); len(changes) != 1 {
		t.Fatalf("change rows left: %d, want the contact's", len(changes))
	}
}

// failingStore fails deleting the messages of one thread id, inside a transaction as the deletion
// runs it.
type failingStore struct {
	store.Store
	fail string
}

var errWipeTest = errors.New("the store failed")

func (f failingStore) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return f.Store.Atomically(ctx, func(tx store.Store) error { return fn(failingStore{Store: tx, fail: f.fail}) })
}

func (f failingStore) DeleteThreadMessages(ctx context.Context, accountID, threadID string) (int64, error) {
	if threadID == f.fail {
		return 0, errWipeTest
	}
	return f.Store.DeleteThreadMessages(ctx, accountID, threadID)
}

// The wipe tells what went one account at a time, as each finishes, and on a failure tells what it
// had deleted from the account it stopped in: the first account is told before the second is
// touched, a failure in the second tells the thread already deleted there, and the wipe stays
// pending, so the next run takes the rest and tells it.
func TestTheWipeTellsEachAccountAsItGoesAndOnAFailure(t *testing.T) {
	st, first, second := wipeEnv(t)
	ctx := context.Background()
	wipeMessage(t, st, first, "f1", "x.y")
	wipeMessage(t, st, second, "s1", "a.b")
	wipeMessage(t, st, second, "s2", "fail.here")
	blobs := BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}
	var got []Wiped
	secondUntouched := false
	err := (&Service{Store: failingStore{Store: st, fail: "fail.here"}, Blobs: blobs}).WipeThreadIDs(ctx, func(w Wiped) {
		if w.AccountID == first {
			msgs, _ := st.ListMessagesByThread(ctx, second, "a.b")
			secondUntouched = len(msgs) == 1
		}
		got = append(got, w)
	})
	if !errors.Is(err, errWipeTest) {
		t.Fatalf("the failure: %v", err)
	}
	if !secondUntouched {
		t.Fatal("the first account was told after the second was touched")
	}
	want := []Wiped{{AccountID: first, Messages: 1}, {AccountID: second, Messages: 1}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("told %+v, want %+v", got, want)
	}
	if pending, _ := st.ThreadIDWipePending(ctx); !pending {
		t.Fatal("a failed wipe is no longer pending")
	}
	got = nil
	if err := (&Service{Store: st, Blobs: blobs}).WipeThreadIDs(ctx, func(w Wiped) { got = append(got, w) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (Wiped{AccountID: second, Messages: 1}) {
		t.Fatalf("the next run told %+v, want the rest of the second account", got)
	}
}
