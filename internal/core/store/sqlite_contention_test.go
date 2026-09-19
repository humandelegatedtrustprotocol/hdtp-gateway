package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// A transaction that reads and then writes, from several goroutines at once, must not fail because
// another one got to the write first. Opened as SQLite opens transactions by default it does —
// most of the time, and at once, whatever `busy_timeout` says — which is why the store asks for
// the write lock at BEGIN (`_txlock=immediate`).
func TestConcurrentReadThenWriteTransactionsAllCommit(t *testing.T) {
	ctx := context.Background()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "contention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, CreateAccountParams{Slug: "busy", DisplayName: "Busy", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 4, 50
	var wg sync.WaitGroup
	failures := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				err := st.Atomically(ctx, func(tx Store) error {
					if _, err := tx.GetAccountByID(ctx, a.ID); err != nil { // the read that makes it an upgrade
						return err
					}
					return tx.InsertMessage(ctx, Message{ID: newID(), AccountID: a.ID, ContactFpr: "sha256:p", MsgID: fmt.Sprintf("w%d-%d", w, i),
						ThreadID: "t", Direction: "in", Sender: "agent", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: 1})
				})
				if err != nil {
					failures <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(failures)
	n := 0
	var first error
	for err := range failures {
		if first == nil {
			first = err
		}
		n++
	}
	if n > 0 {
		t.Fatalf("%d of %d transactions failed, the first with: %v", n, writers*each, first)
	}
	msgs, err := st.ListMessagesByThread(ctx, a.ID, "t")
	if err != nil || len(msgs) != writers*each {
		t.Fatalf("%d messages committed, want %d (%v)", len(msgs), writers*each, err)
	}
}
