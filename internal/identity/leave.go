package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// LeaveResult is what an identity leaving this host erased.
type LeaveResult struct {
	AccountID string
	Slug      string
	// Leaves is how many leaf rows were erased. Every leaf key this host held for the identity
	// went with them, and so did the account's own copy of its current key.
	Leaves int
	// BlobsRemoved is how many media files were deleted: those no other identity on this node
	// still refers to (a blob is content-addressed and shared).
	BlobsRemoved int
}

// LeavePreview is what a leave would erase, read and nothing written: what `account leave` shows
// before the person agrees (the same two steps an import takes). Current is the endpoint the
// identity's current leaf names, "" when it has none.
type LeavePreview struct {
	Slug, Root, Current                   string
	Leaves, Contacts, Threads, MediaFiles int
}

// PreviewLeave reads what Leave would erase for this account.
func (m *Manager) PreviewLeave(ctx context.Context, accountID string) (LeavePreview, error) {
	a, err := m.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return LeavePreview{}, err
	}
	p := LeavePreview{Slug: a.Slug, Root: a.RootFingerprint}
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		return LeavePreview{}, err
	}
	p.Leaves = len(leaves)
	for _, l := range leaves {
		if l.State == LeafCurrent {
			p.Current = l.Endpoint
		}
	}
	cs, err := m.Store.ListContacts(ctx, accountID)
	if err != nil {
		return LeavePreview{}, err
	}
	ts, err := m.Store.ListThreadsByAccount(ctx, accountID)
	if err != nil {
		return LeavePreview{}, err
	}
	bs, err := m.Store.ListBlobs(ctx, accountID)
	if err != nil {
		return LeavePreview{}, err
	}
	p.Contacts, p.Threads, p.MediaFiles = len(cs), len(ts), len(bs)
	return p, nil
}

// Leave erases an identity from this host (HDTP §9, "What a host must do when the person leaves"):
// the leaf keys and every record of the identity go at once, in one transaction. Its address is
// free at once: every identity on this node is its one operator's, the person HDTP §9 keeps a left
// address for, and nothing about the identity is kept to hold it by. The root is the person's and is
// not touched.
//
// The keys are destroyed, not only deleted, where the engine allows it: store.Store.Scrub runs after
// the commit (SPEC §3.9 names what Postgres cannot do).
//
// Every table that names the account by a foreign key is erased by the account row's cascade. The
// ones that name it without one are erased here first: tokens scoped to it, its idempotency
// records, and the per-account settings `settingKeys` names (settings.AccountKeys, and the OAuth
// client credentials of each of its integrations: integrations.ClientKeys), read inside the same
// transaction. Media files are removed after the commit by `removeBlob`
// (messaging.BlobDir.Remove), and only when no other identity still refers to the hash.
//
// Everything the erase decides from — the account, its leaves, its media (what to remove after) —
// is read INSIDE the transaction, so a leaf installed or a file received a moment before cannot be
// missed by the count or left behind on disk.
//
// The audit trail is append-only and is not erased here: its rows naming the account stay in the
// live trail for audit_archive_after, and the hourly sweep then moves them to the identity's own
// archive file (audit.Departed, SPEC §3.11).
func (m *Manager) Leave(ctx context.Context, accountID string, settingKeys func(ctx context.Context, tx store.Store) ([]string, error), removeBlob func(hash string) error) (LeaveResult, error) {
	var res LeaveResult
	var held []store.Blob
	err := m.Store.Atomically(ctx, func(tx store.Store) error {
		a, err := tx.GetAccountByID(ctx, accountID)
		if err != nil {
			return err
		}
		leaves, err := tx.ListLeaves(ctx, accountID)
		if err != nil {
			return err
		}
		res = LeaveResult{AccountID: a.ID, Slug: a.Slug, Leaves: len(leaves)}
		if held, err = tx.ListBlobs(ctx, accountID); err != nil {
			return err
		}
		if _, err := tx.DeleteTokensByAccount(ctx, accountID); err != nil {
			return err
		}
		if _, err := tx.DeleteIdempotencyByAccount(ctx, accountID); err != nil {
			return err
		}
		if _, err := tx.DeleteChangesByAccount(ctx, accountID); err != nil {
			return err
		}
		if settingKeys != nil {
			keys, err := settingKeys(ctx, tx)
			if err != nil {
				return err
			}
			for _, k := range keys {
				if err := tx.DeleteSetting(ctx, k); err != nil {
					return err
				}
			}
		}
		n, err := tx.DeleteAccount(ctx, accountID)
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		return LeaveResult{}, fmt.Errorf("identity: leave %s: %w", accountID, err)
	}
	// The rows are gone, and the leaf keys with them — once their bytes are, too: a DELETE leaves
	// them in the database's files until they are overwritten (store.Store.Scrub).
	var failed []error
	if err := m.Store.Scrub(ctx); err != nil {
		failed = append(failed, fmt.Errorf("the erased leaf keys may remain on disk: %w", err))
	}
	// A media file is shared by hash across identities, so it goes only when no row on this node
	// still refers to it. Counted and removed under the file's lock (store.LockFile), the lock every
	// write that stores a file takes: another identity storing the same bytes meanwhile is counted,
	// or writes them anew after they went.
	for _, b := range held {
		if removeBlob == nil {
			break
		}
		removed := false
		err := m.Store.Atomically(ctx, func(tx store.Store) error {
			removed = false
			if err := tx.LockFile(ctx, b.Hash); err != nil {
				return err
			}
			refs, err := tx.CountBlobRefs(ctx, b.Hash)
			if err != nil || refs > 0 {
				return err
			}
			if err := removeBlob(b.Hash); err != nil {
				return fmt.Errorf("media %s: %w", b.Hash, err)
			}
			removed = true
			return nil
		})
		if err != nil {
			failed = append(failed, err)
			continue
		}
		if removed {
			res.BlobsRemoved++
		}
	}
	if len(failed) > 0 {
		return res, fmt.Errorf("identity: leave %s: the records are erased, and %d thing(s) were not finished: %w", res.Slug, len(failed), errors.Join(failed...))
	}
	return res, nil
}
