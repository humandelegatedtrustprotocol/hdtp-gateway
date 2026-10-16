package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Deleted is what deleting one conversation removed: the answer of every door (the portal's
// POST /thread/delete, the owner MCP's delete_thread), and BatonDeck's deleteThread's shape.
type Deleted struct {
	Status   string `json:"status"`
	ThreadID string `json:"thread_id"`
	// Contact is the fingerprint of the contact the thread was with.
	Contact  string `json:"contact"`
	Messages int64  `json:"messages"`
	Files    int64  `json:"files"`
}

// AuditDetail is what the one `thread_delete` row a deletion writes says after the account: the
// contact, the thread and what went, never the topic or a body. A door that did not delete names
// the thread asked for instead, when its id is of a form of HDTP §7, and otherwise says it was not:
// such an id is free text the caller chose.
func (d Deleted) AuditDetail(threadID string) string {
	if d.Status != "deleted" {
		if CheckThreadID(threadID) != nil {
			return "thread_id:neither_form"
		}
		return "thread_id:" + threadID
	}
	return fmt.Sprintf("contact:%s thread_id:%s messages:%d files:%d", d.Contact, d.ThreadID, d.Messages, d.Files)
}

// DeleteThread deletes one conversation of the account, locally (SPEC §7.9): the thread row (its
// read marker and the names it kept from a removed contact go with it), every message of the
// thread whatever its status (an outbound message still being retried is not tried again), the
// change-log rows naming it, and then the media files no remaining message names (Files.Collect). The
// contact, its permissions, its other threads and the idempotency records (HDTP §13.3) stay, and
// nothing is sent: the peer's copy is the peer's. A message that arrives later on the same
// thread id starts the thread afresh. After the deletion it publishes one EventMessage naming the
// thread on the Bus, when there is one, so a portal showing it wakes and reads it gone; that event's
// change row is the one row naming the thread the log then holds, and the owner MCP's
// wait_for_updates, which reads a change of a thread the account does not hold as no news, does not
// report it.
//
// An id of neither form of HDTP §7 is refused as CheckThreadID refuses it (the empty one is
// ErrBadRequest); a thread the account does not hold, another account's included, is
// store.ErrNotFound.
func (s *Service) DeleteThread(ctx context.Context, accountID, threadID string) (Deleted, error) {
	if err := CheckThreadID(threadID); err != nil {
		return Deleted{}, err
	}
	out, err := s.remove(ctx, accountID, threadID, true)
	if err == nil && s.Bus != nil {
		s.Bus.Publish(Event{Kind: EventMessage, AccountID: accountID, ThreadID: threadID, ContactFpr: out.Contact})
	}
	return out, err
}

// remove is DeleteThread's work. held says the thread row must be there (store.ErrNotFound when it
// is not); the wipe of ids of neither form (WipeThreadIDs) also takes the messages and change rows
// of an id no thread row names.
func (s *Service) remove(ctx context.Context, accountID, threadID string, held bool) (Deleted, error) {
	out := Deleted{Status: "deleted", ThreadID: threadID}
	var bodies []string
	err := s.Store.Atomically(ctx, func(tx store.Store) error {
		th, err := tx.GetThread(ctx, accountID, threadID)
		switch {
		case err == nil:
			out.Contact = th.ContactFpr
		case held || !errors.Is(err, store.ErrNotFound):
			return err
		}
		// The row first: on Postgres its lock makes a message being recorded into this thread wait
		// for this transaction, and then find no thread to touch (Service.record).
		if _, err := tx.DeleteThread(ctx, accountID, threadID); err != nil {
			return err
		}
		if bodies, err = tx.ListThreadMediaBodies(ctx, accountID, threadID); err != nil {
			return err
		}
		if out.Messages, err = tx.DeleteThreadMessages(ctx, accountID, threadID); err != nil {
			return err
		}
		if threadID == "" {
			return nil // a change row's empty thread_id names no thread: a contact's event
		}
		_, err = tx.DeleteChangesByThread(ctx, accountID, threadID)
		return err
	})
	if err != nil {
		return Deleted{}, err
	}
	var hashes []string
	for _, body := range bodies {
		var meta MediaMeta
		if json.Unmarshal([]byte(body), &meta) == nil && meta.Hash != "" {
			hashes = append(hashes, meta.Hash)
		}
	}
	if len(hashes) > 0 {
		// The conversation is gone whatever happens to its files, of any age; Files counts what went
		// now. A file a store failure left is taken by the hourly orphan sweep
		// (Sweeper.CollectOrphans) once nothing names it, whatever the retention window. While any
		// media body of the account does not parse, neither this nor the sweep takes a file (the names
		// in use are unknown), so the files stay until that message is gone; OnError says so.
		files, unreadable, err := Files{Store: s.Store, Blobs: s.Blobs}.Collect(ctx, accountID, hashes, math.MaxInt64)
		out.Files = files
		switch {
		case err != nil:
			s.fail(fmt.Errorf("thread %q deleted, its files not all collected: %w", threadID, err))
		case len(unreadable) > 0:
			s.fail(fmt.Errorf("thread %q deleted; its files were left: %d media bodies of the account do not parse", threadID, len(unreadable)))
		}
	}
	return out, nil
}

func (s *Service) fail(err error) {
	if s.OnError != nil {
		s.OnError(err)
	}
}

// Wiped is what the wipe of thread ids of neither form removed from one account.
type Wiped struct {
	AccountID string
	Threads   int64
	Messages  int64
	Files     int64
}

// WipeThreadIDs deletes, once, every conversation the store holds under a thread id of neither form
// of HDTP §7 (SEP-0006): the thread row with its read marker, its messages, its change rows and the
// files only they name, as DeleteThread deletes one, and also the messages and change rows of such an
// id that no thread row names, the empty id included. Nothing is kept in its place. It runs while
// migration 0005's row says it is pending and then deletes that row; a run that fails part way leaves
// it pending, and the next run takes what is left.
//
// It works one account at a time and tells done what went from each account that lost a thread, a
// message or a file as soon as that account is finished, or as it stops on an error, so what was
// deleted before a failure is told. A process that dies inside one account's deletions tells nothing
// of that account; the next run tells what it deletes.
func (s *Service) WipeThreadIDs(ctx context.Context, done func(Wiped)) error {
	pending, err := s.Store.ThreadIDWipePending(ctx)
	if err != nil || !pending {
		return err
	}
	ids, err := s.Store.ListStoredThreadIDs(ctx)
	if err != nil {
		return err
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].AccountID != ids[j].AccountID {
			return ids[i].AccountID < ids[j].AccountID
		}
		return ids[i].ThreadID < ids[j].ThreadID
	})
	var cur Wiped
	flush := func() {
		if cur.Threads != 0 || cur.Messages != 0 || cur.Files != 0 {
			done(cur)
		}
	}
	for _, id := range ids {
		if hdtpidentity.IsThreadID(id.ThreadID) {
			continue
		}
		if id.AccountID != cur.AccountID {
			flush()
			cur = Wiped{AccountID: id.AccountID}
		}
		gone, err := s.remove(ctx, id.AccountID, id.ThreadID, false)
		if err != nil {
			flush()
			return err
		}
		if gone.Contact != "" {
			cur.Threads++
		}
		cur.Messages += gone.Messages
		cur.Files += gone.Files
	}
	flush()
	return s.Store.EndThreadIDWipe(ctx)
}
