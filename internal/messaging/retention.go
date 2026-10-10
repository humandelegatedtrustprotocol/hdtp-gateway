package messaging

// Per-account retention (SPEC §7.9).
//
// Retention is unlimited by default. When an owner sets a finite window,
// messages older than it and the blobs they were the last reference to are
// deleted — locally, and only locally: there is deliberately no wire protocol
// for remote deletion, so this never tells a peer to forget anything, and the
// UI must not suggest otherwise.
//
// Two properties are worth stating because getting either wrong loses data that
// cannot come back:
//
//   - A blob is content-addressed and shared. Its FILE is removed only once no
//     account still references the hash; an account's own row going away is not
//     enough.
//   - A blob still referenced by a retained message is never touched, even if
//     the blob row itself is older than the window. The message is what keeps it
//     alive, not its own age.
//   - A blob is judged and deleted under its own lock (store.LockFile), in a
//     transaction that asks again whether a message names it. The writes that
//     store a file take the same lock and record the message naming it in the
//     same transaction (MediaService), so a file stored while it is collected
//     is either named when it is judged or written anew after it went.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// RetentionStore is the slice of the store a sweep needs.
type RetentionStore interface {
	ListMediaBodies(ctx context.Context, accountID string) ([]string, error)
	DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error)
	DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error)
	ListBlobs(ctx context.Context, accountID string) ([]store.Blob, error)
	DeleteBlob(ctx context.Context, accountID, hash string) (int64, error)
	CountBlobRefs(ctx context.Context, hash string) (int64, error)
	Atomically(ctx context.Context, fn func(tx store.Store) error) error
	OrphanSweepSince(ctx context.Context) (int64, error)
}

// FileGrace is how old a file's record must be before the orphan sweep (CollectOrphans) takes it
// when nothing names it. Every write that stores a file records the message naming it in the same
// transaction, so an unnamed record written since migration 0003 is garbage at any age; the hour
// is a margin, not a rule the writes need.
const FileGrace = time.Hour

// BlobRemover deletes the bytes behind a hash. BlobDir implements it.
type BlobRemover interface {
	Remove(hash string) error
}

// Sweeper applies retention windows.
type Sweeper struct {
	Store RetentionStore
	Blobs BlobRemover
	Now   func() time.Time
	// Audit records what was deleted. Retention is destructive and local-only,
	// so the audit trail is the only place the deletion is visible afterwards.
	Audit func(action, resource, outcome string)

	mu sync.Mutex
	// unreadableSeen holds the unreadable media bodies already audited (by their SHA-256), so a body
	// that will never parse is reported once by this process, not on every hourly pass.
	unreadableSeen map[string]bool
}

// unreadableNew reports whether any of these unreadable bodies has not been audited yet, and marks
// them all as audited.
func (s *Sweeper) unreadableNew(bodies []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreadableSeen == nil {
		s.unreadableSeen = map[string]bool{}
	}
	fresh := false
	for _, b := range bodies {
		sum := sha256.Sum256([]byte(b))
		k := hex.EncodeToString(sum[:])
		if !s.unreadableSeen[k] {
			s.unreadableSeen[k] = true
			fresh = true
		}
	}
	return fresh
}

// SweepResult reports one account's sweep.
type SweepResult struct {
	Messages int64
	Threads  int64
	Blobs    int64
}

func (s *Sweeper) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sweeper) audit(action, resource, outcome string) {
	if s.Audit != nil {
		s.Audit(action, resource, outcome)
	}
}

// Sweep deletes everything for one account older than `window`. A zero or
// negative window means unlimited retention and deletes nothing — that is the
// default, and the safe reading of an unset value.
func (s *Sweeper) Sweep(ctx context.Context, accountID string, window time.Duration) (SweepResult, error) {
	if window <= 0 {
		return SweepResult{}, nil
	}
	cutoff := s.now().Add(-window).Unix()

	msgs, err := s.Store.DeleteMessagesBefore(ctx, accountID, cutoff)
	if err != nil {
		return SweepResult{}, err
	}
	threads, err := s.Store.DeleteEmptyThreads(ctx, accountID)
	if err != nil {
		return SweepResult{}, err
	}

	// The window's files: those older than it that no retained message names. Files judges both
	// under the file's lock, and spares whatever a retained message still names, whatever its age.
	blobs, err := s.Store.ListBlobs(ctx, accountID)
	if err != nil {
		return SweepResult{}, err
	}
	hashes := make([]string, 0, len(blobs))
	for _, b := range blobs {
		hashes = append(hashes, b.Hash)
	}
	removed, unreadable, err := Files{Store: s.Store, Blobs: s.Blobs}.Collect(ctx, accountID, hashes, cutoff)
	if err != nil {
		return SweepResult{}, err
	}
	if len(unreadable) > 0 {
		// A media message whose body will not parse means the set of live
		// hashes is unknown, and deleting on an unknown set destroys data that
		// cannot come back. Messages were still pruned; blobs wait for a sweep
		// that can see all of them. Audited once per body, not on every pass.
		if s.unreadableNew(unreadable) {
			s.audit("retention_sweep", "account:"+accountID, "blobs_skipped_unreadable_media")
		}
		return SweepResult{Messages: msgs, Threads: threads}, nil
	}
	if msgs > 0 || removed > 0 {
		s.audit("retention_sweep",
			fmt.Sprintf("account:%s messages:%d threads:%d blobs:%d", accountID, msgs, threads, removed), "ok")
	}
	return SweepResult{Messages: msgs, Threads: threads, Blobs: removed}, nil
}

// CollectOrphans deletes the account's files that no message names and whose record is older than
// FileGrace, whatever the retention window, unlimited included: what a deleted conversation could
// not take (a store failure, an unreadable media body). A record written before migration 0003 is
// kept (OrphanSweepSince): an earlier version of the node stored a fetched link's file without
// recording it on the message, and that file is the owner's content, which nothing in its record
// can name. It returns how many records went, and audits them as a retention_sweep.
func (s *Sweeper) CollectOrphans(ctx context.Context, accountID string) (int64, error) {
	since, err := s.Store.OrphanSweepSince(ctx)
	if err != nil {
		return 0, err
	}
	blobs, err := s.Store.ListBlobs(ctx, accountID)
	if err != nil {
		return 0, err
	}
	hashes := make([]string, 0, len(blobs))
	for _, b := range blobs {
		// A record written before migration 0003 is kept: a link fetched then was not recorded on
		// its message, nothing names the file, and nothing in the record says which message would.
		if b.CreatedAt >= since {
			hashes = append(hashes, b.Hash)
		}
	}
	removed, unreadable, err := Files{Store: s.Store, Blobs: s.Blobs}.Collect(ctx, accountID, hashes, s.now().Add(-FileGrace).Unix())
	if err != nil {
		return removed, err
	}
	if len(unreadable) > 0 {
		if s.unreadableNew(unreadable) {
			s.audit("retention_sweep", "account:"+accountID, "blobs_skipped_unreadable_media")
		}
		return 0, nil
	}
	if removed > 0 {
		s.audit("retention_sweep", fmt.Sprintf("account:%s blobs:%d", accountID, removed), "ok")
	}
	return removed, nil
}

// Files collects the media files nothing names any more: one implementation for the retention
// sweep, the orphan sweep and a deleted conversation (Service.DeleteThread). The other place a file
// goes is an identity leaving, which removes every file only it held (identity.Manager.Leave) under
// the same lock; a send or a fetch that is refused writes no file to remove.
type Files struct {
	Store RetentionStore
	// Blobs removes the bytes; nil deletes the records and leaves the files (tests).
	Blobs BlobRemover
}

// Collect deletes the account's record of each candidate file that is older than cutoff (unix
// seconds) and that no media message of the account names, and the file itself once no account's
// record names it (the store is content-addressed and shared). Each file is judged and deleted in a
// transaction that holds the file's lock (store.LockFile), the lock MediaService takes to store a
// file, so a file stored again while it is collected is either seen (its record is young, or a
// message names it) or stored after the deletion, writing its record and bytes anew. It returns how
// many records went. unreadable holds the media bodies that do not parse; when there are any, nothing
// is deleted, because a media message's body that does
// not parse: the set of names still in use is then unknown, and deleting on an unknown set destroys
// what cannot come back.
func (f Files) Collect(ctx context.Context, accountID string, candidates []string, cutoff int64) (removed int64, unreadable []string, err error) {
	live, unreadable, err := referencedHashes(ctx, f.Store, accountID)
	if err != nil || len(unreadable) > 0 {
		return 0, unreadable, err
	}
	for _, hash := range candidates {
		if live[hash] {
			continue
		}
		var gone bool
		err := f.Store.Atomically(ctx, func(tx store.Store) error {
			gone = false
			if err := tx.LockFile(ctx, hash); err != nil {
				return err
			}
			b, err := tx.GetBlob(ctx, accountID, hash)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil // this account holds no record of it: nothing of its to remove
				}
				return err
			}
			if b.CreatedAt >= cutoff {
				return nil // stored again, or new: a message naming it may be on its way
			}
			// Asked again under the lock: a message recorded since the read above names it.
			if named, err := tx.MediaNames(ctx, accountID, hash); err != nil || named {
				return err
			}
			if _, err := tx.DeleteBlob(ctx, accountID, hash); err != nil {
				return err
			}
			gone = true
			// The file is shared across accounts; it goes only when the last row does.
			refs, err := tx.CountBlobRefs(ctx, hash)
			if err != nil {
				return err
			}
			if refs == 0 && f.Blobs != nil {
				if err := f.Blobs.Remove(hash); err != nil {
					return fmt.Errorf("retention: removing blob %s: %w", hash, err)
				}
			}
			return nil
		})
		if err != nil {
			return removed, nil, err
		}
		if gone {
			removed++
		}
	}
	return removed, nil, nil
}

// referencedHashes collects the blob hashes retained messages still point at, and the media bodies
// that could not be parsed: when there are any, the caller must leave blobs alone rather than guess.
func referencedHashes(ctx context.Context, st RetentionStore, accountID string) (map[string]bool, []string, error) {
	out := map[string]bool{}
	var unreadable []string
	// The media messages and only those. This asked for every thread and then every message of
	// every thread, which on a large account was the whole of a sweep's cost.
	bodies, err := st.ListMediaBodies(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	for _, body := range bodies {
		var meta MediaMeta
		if err := json.Unmarshal([]byte(body), &meta); err != nil {
			unreadable = append(unreadable, body)
			continue
		}
		if meta.Hash != "" {
			out[meta.Hash] = true
		}
	}
	return out, unreadable, nil
}
