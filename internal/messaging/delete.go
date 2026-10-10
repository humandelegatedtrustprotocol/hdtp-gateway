package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Deleted is what deleting one conversation removed: the answer of every door (the portal's
// POST /threads/{id}/delete, the owner MCP's delete_thread), and BatonDeck's deleteThread's shape.
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
// the thread asked for instead.
func (d Deleted) AuditDetail(threadID string) string {
	if d.Status != "deleted" {
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
// An empty id is ErrBadRequest; a thread the account does not hold, another account's included,
// is store.ErrNotFound.
func (s *Service) DeleteThread(ctx context.Context, accountID, threadID string) (Deleted, error) {
	if threadID == "" {
		return Deleted{}, fmt.Errorf("%w: thread_id required", ErrBadRequest)
	}
	out := Deleted{Status: "deleted", ThreadID: threadID}
	var bodies []string
	err := s.Store.Atomically(ctx, func(tx store.Store) error {
		th, err := tx.GetThread(ctx, accountID, threadID)
		if err != nil {
			return err
		}
		out.Contact = th.ContactFpr
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
