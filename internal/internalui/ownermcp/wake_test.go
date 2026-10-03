package ownermcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// rowsStore counts the rows every read of the store hands back to the wait: a list is as many rows
// as it returns, a single row or a count is one.
type rowsStore struct {
	store.Store
	rows int
}

func (s *rowsStore) ListContacts(ctx context.Context, a string) ([]store.Contact, error) {
	r, err := s.Store.ListContacts(ctx, a)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) CountContactsByStatus(ctx context.Context, a, st string) (int64, error) {
	s.rows++
	return s.Store.CountContactsByStatus(ctx, a, st)
}
func (s *rowsStore) ListThreadsByAccount(ctx context.Context, a string) ([]store.Thread, error) {
	r, err := s.Store.ListThreadsByAccount(ctx, a)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) AccountChangesAfter(ctx context.Context, a string, after int64, limit int) ([]store.Change, error) {
	r, err := s.Store.AccountChangesAfter(ctx, a, after, limit)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) ListPendingAddresses(ctx context.Context, a string) ([]store.PendingAddress, error) {
	r, err := s.Store.ListPendingAddresses(ctx, a)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) ListOpenPendingRequests(ctx context.Context, a string, now int64) ([]store.PendingRequest, error) {
	r, err := s.Store.ListOpenPendingRequests(ctx, a, now)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) ListIntegrations(ctx context.Context, a string) ([]store.Integration, error) {
	r, err := s.Store.ListIntegrations(ctx, a)
	s.rows += len(r)
	return r, err
}
func (s *rowsStore) GetThread(ctx context.Context, a, id string) (store.Thread, error) {
	s.rows++
	return s.Store.GetThread(ctx, a, id)
}
func (s *rowsStore) GetContact(ctx context.Context, a, fpr string) (store.Contact, error) {
	s.rows++
	return s.Store.GetContact(ctx, a, fpr)
}
func (s *rowsStore) UnreadCount(ctx context.Context, a, th string) (int64, error) {
	s.rows++
	return s.Store.UnreadCount(ctx, a, th)
}

// One wake of the owner's wait reads what changed since the cursor and the queues only the owner
// clears — never the whole contact list: at 1, 300 and 2000 contacts (one of them waiting for
// approval, the rest active) and one new message, the wake reads the same number of rows. And it
// answers what it answered when it counted by reading every contact: the same threads, the same
// count of requests, the same cursor.
func TestAWakeReadsTheSameRowsAt1And300And2000Contacts(t *testing.T) {
	ctx := context.Background()
	var perWake []int
	for _, n := range []int{1, 300, 2000} {
		e := newEnv(t)
		for i := 0; i < n; i++ {
			status := "active"
			if i == 0 {
				status = "pending_in"
			}
			if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: fmt.Sprintf("sha256:c%05d", i),
				SPKI: []byte{1}, Status: status, DisplayName: fmt.Sprintf("C%d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		_, since, err := e.st.ChangeBounds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:c00001", messaging.DirIn, messaging.Input{
			MsgID: "m-1", Text: "hello", Sender: "agent", Origin: messaging.OriginPeer}); err != nil {
			t.Fatal(err)
		}
		counting := &rowsStore{Store: e.st}
		d := e.deps
		d.Store = counting
		res, err := d.changesSince(ctx, e.acctA, since)
		if err != nil {
			t.Fatal(err)
		}
		perWake = append(perWake, counting.rows)

		// The answer counting every contact gave.
		all, err := e.st.ListContacts(ctx, e.acctA)
		if err != nil {
			t.Fatal(err)
		}
		var waiting int64
		for _, c := range all {
			if c.Status == "pending_in" {
				waiting++
			}
		}
		_, newest, _ := e.st.ChangeBounds(ctx)
		if res.Waiting != waiting || len(res.Threads) != 1 || res.Threads[0].ContactFpr != "sha256:c00001" || res.Cursor != newest {
			t.Fatalf("at %d contacts the wake answered waiting %d, threads %+v, cursor %d; counting every contact gives %d, one thread, cursor %d",
				n, res.Waiting, res.Threads, res.Cursor, waiting, newest)
		}
	}
	if perWake[0] != perWake[1] || perWake[1] != perWake[2] {
		t.Fatalf("a wake read %v rows at 1, 300 and 2000 contacts: it grows with the list", perWake)
	}
	t.Logf("rows read per wake at 1, 300, 2000 contacts: %v", perWake)
}
