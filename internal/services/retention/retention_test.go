package retention

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/settings"
)

// The sweeper is a blocking function: it does not return while a pass is running, which is what
// lets `serve` wait for it. And a pass cut short by the node stopping has not failed, so it says
// nothing — before this, every interrupted pass printed a store error for a store that was fine.
func TestTheSweeperReturnsOnlyWhenItsPassHasAndAStoppingNodeIsNotAFailure(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	var stderr lockedTestBuf
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		Run(ctx, nil, st, &core.Config{DataDir: dir}, func(string, string, string) {}, &stderr,
			func(context.Context) { close(entered); <-release }, nil, nil, nil)
	}()

	<-entered // the startup pass is running, inside the leaf-retirement step
	cancel()  // …and the node is told to stop
	select {
	case <-returned:
		t.Fatal("the sweeper returned while its pass was still running: serve would close the store under it")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweeper did not return after its pass finished and its context had ended")
	}
	// The rest of that pass ran against a cancelled context. Every store call in it failed, and none
	// of those failures is news.
	if got := stderr.String(); got != "" {
		t.Fatalf("a pass interrupted by shutdown reported errors:\n%s", got)
	}
}

type lockedTestBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedTestBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedTestBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// SPEC §9.1: an unanswered request expires, 30 days by default and per account when the owner
// says otherwise, and the relationship returns to none (review N-03). Nothing did this: a request
// nobody answered waited for ever, and so did one of ours that nobody answered.
func TestTheSweepExpiresRequestsNobodyAnswered(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()
	bg := context.Background()
	a, err := st.CreateAccount(bg, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateAccount(bg, store.CreateAccountParams{Slug: "b", DisplayName: "B", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	// b's owner waits a week.
	if err := st.PutSetting(bg, store.Setting{Key: settings.ContactsKeyRequestExpiry(b.ID), Value: "7"}); err != nil {
		t.Fatal(err)
	}
	day := int64(24 * 60 * 60)
	now := time.Now().Unix()
	rows := []struct {
		acct, fpr, status string
		age               int64
	}{
		{a.ID, "sha256:a-old-in", "pending_in", 31 * day},
		{a.ID, "sha256:a-old-out", "pending_out", 31 * day},
		{a.ID, "sha256:a-young-in", "pending_in", 8 * day},
		{a.ID, "sha256:a-old-active", "active", 90 * day},
		{b.ID, "sha256:b-week-in", "pending_in", 8 * day},
	}
	for _, r := range rows {
		if _, err := st.InsertContact(bg, store.Contact{AccountID: r.acct, Fingerprint: r.fpr, Status: r.status, CreatedAt: now - r.age}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var audited, dropped []string
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, settings.New(st, nil, nil, nil), st, &core.Config{DataDir: dir},
			func(action, resource, outcome string) {
				if action == "contact_expire" {
					mu.Lock()
					audited = append(audited, resource)
					mu.Unlock()
				}
			}, io.Discard, nil, nil,
			func(_ context.Context, _, fpr string) error {
				mu.Lock()
				dropped = append(dropped, fpr)
				mu.Unlock()
				return nil
			}, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(audited)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	gone := func(acct, fpr string) bool {
		_, err := st.GetContact(bg, acct, fpr)
		return err != nil
	}
	for _, r := range rows {
		want := r.fpr == "sha256:a-old-in" || r.fpr == "sha256:a-old-out" || r.fpr == "sha256:b-week-in"
		if gone(r.acct, r.fpr) != want {
			t.Errorf("%s (%s, %d days old): gone=%v, want %v", r.fpr, r.status, r.age/day, !want, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 3 || !slices.ContainsFunc(audited, func(s string) bool { return strings.Contains(s, "sha256:a-old-out status:pending_out") }) {
		t.Errorf("audit rows: %v", audited)
	}
	if !slices.Contains(dropped, "sha256:a-old-out") {
		t.Errorf("an expired approach of ours kept its composed surface: %v", dropped)
	}
}

// The retention pass runs only on the process that holds its lease (SPEC §11.1): at start, a
// process that does not lead sweeps nothing, and one that leads sweeps.
func TestTheRetentionPassRunsOnlyWhileItLeads(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()
	for _, lead := range []bool{false, true} {
		var swept sync.WaitGroup
		ran := make(chan struct{}, 1)
		ctx, cancel := context.WithCancel(context.Background())
		swept.Go(func() {
			Run(ctx, nil, st, &core.Config{DataDir: dir}, func(string, string, string) {}, io.Discard,
				func(context.Context) { ran <- struct{}{} }, nil, nil,
				func(context.Context) bool { return lead })
		})
		var did bool
		select {
		case <-ran:
			did = true
		case <-time.After(time.Second):
		}
		cancel()
		swept.Wait()
		if did != lead {
			t.Fatalf("leading %v, the pass at start ran %v", lead, did)
		}
	}
}

// Unlimited retention (no window set) keeps every message and takes the files no message names
// once they are older than messaging.FileGrace: the pass runs the orphan sweep for every account.
func TestThePassTakesUnnamedFilesUnderUnlimitedRetention(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()
	bg := context.Background()
	a, err := st.CreateAccount(bg, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &core.Config{DataDir: dir}
	blobs := messaging.BlobDir{Root: cfg.Blobs()}
	// The node was upgraded three hours ago (migration 0003's row; raw SQL, as nothing else writes it).
	since := time.Now().Add(-3 * messaging.FileGrace).Unix()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE orphan_sweep SET since = ?", since); err != nil {
		t.Fatal(err)
	}
	db.Close()
	file := func(data string, createdAt int64) string {
		hash, err := blobs.Put([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.InsertBlob(bg, store.Blob{AccountID: a.ID, Hash: hash, Size: int64(len(data)), CreatedAt: createdAt}); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	hash := file("nothing names this file", time.Now().Add(-2*messaging.FileGrace).Unix())
	// A link the node fetched before the upgrade: unnamed, the owner's, kept.
	before := file("fetched before the upgrade", since-3600)
	var mu sync.Mutex
	var swept []string
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, settings.New(st, nil, nil, nil), st, cfg, func(action, resource, outcome string) {
			if action == "retention_sweep" {
				mu.Lock()
				swept = append(swept, resource+" "+outcome)
				mu.Unlock()
			}
		}, io.Discard, nil, nil, nil, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(swept)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if _, err := blobs.Get(hash); err == nil {
		t.Fatal("a file nothing names outlived the pass under unlimited retention")
	}
	if _, err := blobs.Get(before); err != nil {
		t.Fatal("the pass took a file from before the upgrade")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(swept) != 1 || swept[0] != "account:"+a.ID+" blobs:1 ok" {
		t.Fatalf("audit rows: %v", swept)
	}
}
