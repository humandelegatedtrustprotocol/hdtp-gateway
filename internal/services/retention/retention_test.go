package retention

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/services/settings"
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
			func(context.Context) { close(entered); <-release }, nil, nil)
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
			})
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

// An address an identity left is reserved until the last leaf issued for it expires (PACT §9), and
// no longer: the sweep drops a reservation whose date has passed and keeps one that has not.
func TestTheSweepDropsAReservationOnlyOnceItsLeafHasExpired(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()
	bg := context.Background()
	now := time.Now().Unix()
	for _, v := range []store.VacatedAddress{
		{Endpoint: "https://n.example/a/gone/mcp", Slug: "gone", UntilAt: now - 60, At: now - 100},
		{Endpoint: "https://n.example/a/held/mcp", Slug: "held", UntilAt: now + 24*3600, At: now - 100},
	} {
		if err := st.UpsertVacatedAddress(bg, v); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, settings.New(st, nil, nil, nil), st, &core.Config{DataDir: dir}, func(string, string, string) {}, io.Discard, nil, nil, nil)
	}()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		left, err := st.ListVacatedAddresses(bg)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) == 1 && left[0].Slug == "held" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the sweep the reservations are %+v, want only the live one", left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
