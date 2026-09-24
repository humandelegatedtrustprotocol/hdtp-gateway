package contacts

import (
	"context"
	"errors"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// staleOnce answers the first GetContact with the row as it was when the owner's decision read it,
// and every later read (the re-read after a guarded write moved nothing) with the row as it is.
// That is the window between an owner's read and write, held open deterministically.
type staleOnce struct {
	store.Store
	was  store.Contact
	used bool
}

func (s *staleOnce) GetContact(ctx context.Context, accountID, fpr string) (store.Contact, error) {
	if !s.used {
		s.used = true
		return s.was, nil
	}
	return s.Store.GetContact(ctx, accountID, fpr)
}

// Review of #22, finding 2: the owner's decisions wrote the status unguarded, so a row that moved
// between the read and the write was overwritten, and a row that went answered the store's own
// words (the owner MCP's "internal").
func TestOwnerDecisionsWriteAgainstTheStatusTheyRead(t *testing.T) {
	ctx := context.Background()
	const fpr = "sha256:racer"

	t.Run("reject over a request that became a contact meanwhile", func(t *testing.T) {
		e := newEnv(t)
		was, _ := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fpr, Status: "pending_in", SPKI: []byte{1}})
		// A peer redeemed an auto-accept invite over the waiting row: it is active now.
		if err := e.st.UpdateContactStatus(ctx, e.account, fpr, "active"); err != nil {
			t.Fatal(err)
		}
		told := false
		o := Owner{Manager: &Manager{Store: &staleOnce{Store: e.st, was: was}}, TellRejected: func(context.Context, string, string) error { told = true; return nil }}
		if _, err := o.Reject(ctx, e.account, fpr); !errors.Is(err, ErrWrongState) {
			t.Fatalf("reject answered %v, want ErrWrongState", err)
		}
		if c, _ := e.st.GetContact(ctx, e.account, fpr); c.Status != "active" {
			t.Fatalf("the contact is %s; the reject demoted a contact it never decided on", c.Status)
		}
		if told {
			t.Fatal("an active peer was told they were rejected")
		}
	})

	t.Run("approve of a request the expiry removed meanwhile", func(t *testing.T) {
		e := newEnv(t)
		was, _ := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fpr, Status: "pending_in", SPKI: []byte{1}})
		if err := e.st.DeleteContact(ctx, e.account, fpr); err != nil {
			t.Fatal(err)
		}
		o := Owner{Manager: &Manager{Store: &staleOnce{Store: e.st, was: was}}}
		if _, err := o.Approve(ctx, e.account, fpr, ""); !errors.Is(err, ErrUnknownContact) {
			t.Fatalf("approve answered %v, want ErrUnknownContact", err)
		}
	})

	t.Run("unblock of a row unblocked elsewhere meanwhile", func(t *testing.T) {
		e := newEnv(t)
		was, _ := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fpr, Status: "active", SPKI: []byte{1}})
		_ = e.st.UpdateContactStatus(ctx, e.account, fpr, "blocked")
		was.Status, was.EverActive = "blocked", true
		// Meanwhile it went back to active on another surface.
		_ = e.st.UpdateContactStatus(ctx, e.account, fpr, "active")
		o := Owner{Manager: &Manager{Store: &staleOnce{Store: e.st, was: was}}}
		if _, err := o.Unblock(ctx, e.account, fpr); !errors.Is(err, ErrWrongState) {
			t.Fatalf("unblock answered %v, want ErrWrongState", err)
		}
	})

	t.Run("block of a row blocked elsewhere meanwhile is the outcome asked for", func(t *testing.T) {
		e := newEnv(t)
		was, _ := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fpr, Status: "active", SPKI: []byte{1}})
		_ = e.st.UpdateContactStatus(ctx, e.account, fpr, "blocked")
		o := Owner{Manager: &Manager{Store: &staleOnce{Store: e.st, was: was}}}
		if d, err := o.Block(ctx, e.account, fpr); err != nil || d.Status != "blocked" {
			t.Fatalf("block answered %+v, %v", d, err)
		}
	})

	t.Run("the control: an unraced reject still rejects and tells", func(t *testing.T) {
		e := newEnv(t)
		_, _ = e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fpr, Status: "pending_in", SPKI: []byte{1}})
		told := false
		o := Owner{Manager: e.m, TellRejected: func(context.Context, string, string) error { told = true; return nil }}
		if d, err := o.Reject(ctx, e.account, fpr); err != nil || d.Status != "blocked" || !told {
			t.Fatalf("reject: %+v %v told=%v", d, err, told)
		}
	})
}
