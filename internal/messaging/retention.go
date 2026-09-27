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
//   - An unreferenced blob is collected only once it is ALSO past the window. A
//     blob row is written before the message that references it, so "nothing
//     points at it" is a normal, momentary state for brand-new media rather than
//     evidence that it is garbage.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// RetentionStore is the slice of the store a sweep needs.
type RetentionStore interface {
	ListMediaBodies(ctx context.Context, accountID string) ([]string, error)
	DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error)
	DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error)
	ListBlobs(ctx context.Context, accountID string) ([]store.Blob, error)
	DeleteBlob(ctx context.Context, accountID, hash string) (int64, error)
	CountBlobRefs(ctx context.Context, hash string) (int64, error)
}

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

	// Whatever is still referenced by a retained message stays, whatever its age.
	live, readable, err := s.referencedHashes(ctx, accountID)
	if err != nil {
		return SweepResult{}, err
	}
	if !readable {
		// A media message whose body will not parse means the set of live
		// hashes is unknown, and deleting on an unknown set destroys data that
		// cannot come back. Messages were still pruned; blobs wait for a sweep
		// that can see all of them.
		s.audit("retention_sweep", "account:"+accountID, "blobs_skipped_unreadable_media")
		return SweepResult{Messages: msgs, Threads: threads}, nil
	}
	blobs, err := s.Store.ListBlobs(ctx, accountID)
	if err != nil {
		return SweepResult{}, err
	}
	var removed int64
	for _, b := range blobs {
		if live[b.Hash] {
			continue
		}
		// Age is a condition, not a detail. A blob row exists BEFORE the message
		// that references it — `ReceiveInline` writes the two separately — so
		// "unreferenced" alone would destroy media that arrived seconds ago, in
		// the gap between those writes. Only content that is both unreferenced
		// AND older than the window is collectable.
		if b.CreatedAt >= cutoff {
			continue
		}
		if _, err := s.Store.DeleteBlob(ctx, accountID, b.Hash); err != nil {
			return SweepResult{}, err
		}
		removed++
		// The file is shared across accounts; it goes only when the last row does.
		refs, err := s.Store.CountBlobRefs(ctx, b.Hash)
		if err != nil {
			return SweepResult{}, err
		}
		if refs == 0 && s.Blobs != nil {
			if err := s.Blobs.Remove(b.Hash); err != nil {
				return SweepResult{}, fmt.Errorf("retention: removing blob %s: %w", b.Hash, err)
			}
		}
	}
	if msgs > 0 || removed > 0 {
		s.audit("retention_sweep",
			fmt.Sprintf("account:%s messages:%d threads:%d blobs:%d", accountID, msgs, threads, removed), "ok")
	}
	return SweepResult{Messages: msgs, Threads: threads, Blobs: removed}, nil
}

// referencedHashes collects the blob hashes retained messages still point at.
// It reports readable=false if any media body could not be parsed: the caller
// must then leave blobs alone rather than guess.
func (s *Sweeper) referencedHashes(ctx context.Context, accountID string) (map[string]bool, bool, error) {
	out := map[string]bool{}
	readable := true
	// The media messages and only those. This asked for every thread and then every message of
	// every thread, which on a large account was the whole of a sweep's cost.
	bodies, err := s.Store.ListMediaBodies(ctx, accountID)
	if err != nil {
		return nil, false, err
	}
	for _, body := range bodies {
		var meta MediaMeta
		if err := json.Unmarshal([]byte(body), &meta); err != nil {
			readable = false
			continue
		}
		if meta.Hash != "" {
			out[meta.Hash] = true
		}
	}
	return out, readable, nil
}
