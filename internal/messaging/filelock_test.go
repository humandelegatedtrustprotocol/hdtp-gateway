package messaging

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The two callers of store.LockFile that a collection races, held to the lock on both engines.
// SQLite's one writer serializes them whatever the lock does; on Postgres the advisory lock is
// what does, and each scenario fails there without its caller's lock.
func TestFileLockInterleavingsOnSQLite(t *testing.T) {
	fileLockInterleavings(t, func(t *testing.T) store.Store {
		st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "l.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return st
	})
}

// HDTP_TEST_POSTGRES_DSN, as the store's own Postgres suite (the pre-push hook sets it).
func TestFileLockInterleavingsOnPostgres(t *testing.T) {
	dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("HDTP_TEST_POSTGRES_DSN not set")
	}
	n := 0
	fileLockInterleavings(t, func(t *testing.T) store.Store {
		n++
		name := fmt.Sprintf("hdtp_filelock_%d", n)
		admin, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
		if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		admin.Close(context.Background())
		i := strings.LastIndex(dsn, "/")
		rest := dsn[i+1:]
		db := dsn[:i+1] + name
		if j := strings.Index(rest, "?"); j >= 0 {
			db += rest[j:]
		}
		st, err := store.OpenPostgres(context.Background(), db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return st
	})
}

// countPause is a store whose transactions pause after counting a file's references, until told to
// go on or a second has passed: the moment between a collection's count and its removal.
type countPause struct {
	store.Store
	paused chan struct{}
	resume chan struct{}
}

func (c *countPause) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return c.Store.Atomically(ctx, func(tx store.Store) error { return fn(&countPauseTx{Store: tx, c: c}) })
}

type countPauseTx struct {
	store.Store
	c *countPause
}

func (t *countPauseTx) CountBlobRefs(ctx context.Context, hash string) (int64, error) {
	n, err := t.Store.CountBlobRefs(ctx, hash)
	close(t.c.paused)
	select {
	case <-t.c.resume:
	case <-time.After(time.Second):
	}
	return n, err
}

// commitPause is a store whose transactions pause after their work and before they commit, until
// told to go on or a second has passed: a file's bytes written, its record not yet visible.
type commitPause struct {
	store.Store
	paused chan struct{}
	resume chan struct{}
}

func (c *commitPause) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return c.Store.Atomically(ctx, func(tx store.Store) error {
		err := fn(tx)
		close(c.paused)
		select {
		case <-c.resume:
		case <-time.After(time.Second):
		}
		return err
	})
}

// fileLockInterleavings holds both callers of store.LockFile to it, on an engine where the lock is
// what serializes them (Postgres; SQLite's one writer serializes them anyway). Each scenario ends
// with a message naming a file whose bytes must still be there.
func fileLockInterleavings(t *testing.T, newStore func(t *testing.T) store.Store) {
	setup := func(t *testing.T) (store.Store, BlobDir, string, string, []byte, string) {
		s := newStore(t)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "fl-a", DisplayName: "A", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "fl-b", DisplayName: "B", Algo: "p256"})
		blobs := BlobDir{Root: t.TempDir()}
		data := []byte("bytes two identities hold")
		hash, err := blobs.Put(data)
		if err != nil {
			t.Fatal(err)
		}
		// A's record of the file, old and named by nothing: a collection takes it.
		if err := s.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: hash, Size: int64(len(data)), CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		return s, blobs, a.ID, b.ID, data, hash
	}
	receive := func(st ConversationStore, blobs BlobDir, accountID string, data []byte) error {
		media := &MediaService{Store: st, Blobs: blobs}
		_, err := media.ReceiveInline(context.Background(), &Service{Store: st}, accountID, "sha256:peer",
			Input{Origin: OriginPeer, MsgID: "m1", Sender: SenderHuman}, "f", "text/plain", data)
		return err
	}
	named := func(t *testing.T, s store.Store, blobs BlobDir, accountID, hash string) {
		t.Helper()
		if ok, err := s.MediaNames(context.Background(), accountID, hash); err != nil || !ok {
			t.Fatalf("no message of %s names the file (%v)", accountID, err)
		}
		if _, err := blobs.Get(hash); err != nil {
			t.Fatalf("a message names the file and its bytes are gone: %v", err)
		}
	}

	// keepIn's lock: B stores the same bytes while A's collection is between its count and its
	// removal. Without it, B's write finds the bytes there, commits, and A then removes them.
	t.Run("AStoreWaitsForACollection", func(t *testing.T) {
		s, blobs, a, b, data, hash := setup(t)
		pause := &countPause{Store: s, paused: make(chan struct{}), resume: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			_, _, err := Files{Store: pause, Blobs: blobs}.Collect(context.Background(), a, []string{hash}, 2)
			done <- err
		}()
		<-pause.paused
		stored := make(chan error, 1)
		go func() { stored <- receive(s, blobs, b, data) }()
		var storeErr error
		finished := false
		select {
		case storeErr = <-stored:
			// B finished while A was paused: it took no lock A held.
			finished = true
			close(pause.resume)
		case <-time.After(500 * time.Millisecond):
			// B waits; A goes on by itself after its second.
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !finished {
			storeErr = <-stored
		}
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		named(t, s, blobs, b, hash)
	})

	// Collect's lock: A collects while B's store has written the bytes and not yet committed its
	// record. Without it, A counts no other record and removes the bytes B is about to name.
	t.Run("ACollectionWaitsForAStore", func(t *testing.T) {
		s, blobs, a, b, data, hash := setup(t)
		pause := &commitPause{Store: s, paused: make(chan struct{}), resume: make(chan struct{})}
		stored := make(chan error, 1)
		go func() { stored <- receive(pause, blobs, b, data) }()
		<-pause.paused
		collected := make(chan error, 1)
		go func() {
			_, _, err := Files{Store: s, Blobs: blobs}.Collect(context.Background(), a, []string{hash}, 2)
			collected <- err
		}()
		var collectErr error
		finished := false
		select {
		case collectErr = <-collected:
			finished = true
			close(pause.resume)
		case <-time.After(500 * time.Millisecond):
		}
		if err := <-stored; err != nil {
			t.Fatal(err)
		}
		if !finished {
			collectErr = <-collected
		}
		if collectErr != nil {
			t.Fatal(collectErr)
		}
		named(t, s, blobs, b, hash)
	})
}
