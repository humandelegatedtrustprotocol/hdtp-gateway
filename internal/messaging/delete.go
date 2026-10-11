package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

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
// thread id starts the thread afresh.
//
// An id of neither form of HDTP §7 is refused as CheckThreadID refuses it (the empty one is
// ErrBadRequest); a thread the account does not hold, another account's included, is
// store.ErrNotFound.
func (s *Service) DeleteThread(ctx context.Context, accountID, threadID string) (Deleted, error) {
	if err := CheckThreadID(threadID); err != nil {
		return Deleted{}, err
	}
	return s.remove(ctx, accountID, threadID, true)
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
		// The conversation is gone whatever happens to its files, of any age. One this collection
		// could not take (a store failure, an unreadable media body elsewhere) is left; the hourly
		// orphan sweep (Sweeper.CollectOrphans) takes it once nothing names it, whatever the retention
		// window. Files counts what went now.
		files, _, err := Files{Store: s.Store, Blobs: s.Blobs}.Collect(ctx, accountID, hashes, math.MaxInt64)
		out.Files = files
		if err != nil && s.OnError != nil {
			s.OnError(fmt.Errorf("thread %s deleted, its files not all collected: %w", threadID, err))
		}
	}
	return out, nil
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
// id that no thread row names. Nothing is kept in its place. It runs when migration 0005 scheduled it
// and records that it ran; a run that fails part way leaves it scheduled, and the next start runs it
// again over what is left. It answers what went, one Wiped per account that lost a thread, a
// message or a file.
func (s *Service) WipeThreadIDs(ctx context.Context) ([]Wiped, error) {
	pending, err := s.Store.ThreadIDWipePending(ctx)
	if err != nil || !pending {
		return nil, err
	}
	ids, err := s.Store.ListStoredThreadIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []Wiped
	at := map[string]int{}
	for _, id := range ids {
		if hdtpidentity.IsThreadID(id.ThreadID) {
			continue
		}
		gone, err := s.remove(ctx, id.AccountID, id.ThreadID, false)
		if err != nil {
			return out, err
		}
		if gone.Contact == "" && gone.Messages == 0 && gone.Files == 0 {
			continue
		}
		i, ok := at[id.AccountID]
		if !ok {
			i = len(out)
			at[id.AccountID] = i
			out = append(out, Wiped{AccountID: id.AccountID})
		}
		if gone.Contact != "" {
			out[i].Threads++
		}
		out[i].Messages += gone.Messages
		out[i].Files += gone.Files
	}
	return out, s.Store.EndThreadIDWipe(ctx)
}
