package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// LeaveResult is what an identity leaving this host erased and what it left reserved.
type LeaveResult struct {
	AccountID string
	Slug      string
	// Vacated is one row per endpoint the identity's leaves named whose last leaf is still live:
	// the address stays reserved until then (PACT §9).
	Vacated []store.VacatedAddress
	// Leaves is how many leaf rows were erased. Every leaf key this host held for the identity
	// went with them, and so did the account's own copy of its current key.
	Leaves int
	// BlobsRemoved is how many media files were deleted: those no other identity on this node
	// still refers to (a blob is content-addressed and shared).
	BlobsRemoved int
}

// Leave erases an identity from this host (PACT §9, "What a host must do when the person leaves"):
// the leaf keys and every record of the identity go at once, in one transaction, and the address
// is kept reserved — by a row that holds the endpoint, its slug and a date, and nothing that
// names the identity — until the last leaf issued for it has expired.
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
// Everything the erase decides from — the account, its leaves (what to reserve), its media (what
// to remove after) — is read INSIDE the transaction, so a leaf installed or a file received a
// moment before cannot be missed by the reservation or left behind on disk.
//
// The audit trail is append-only and is not erased: its rows keep the account id.
func (m *Manager) Leave(ctx context.Context, accountID string, settingKeys func(ctx context.Context, tx store.Store) ([]string, error), removeBlob func(hash string) error, now time.Time) (LeaveResult, error) {
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
		// The last leaf issued for each address: a leaf this host installed (a pending request has none).
		until := map[string]int64{}
		for _, l := range leaves {
			if len(l.Leaf) == 0 || l.Endpoint == "" {
				continue
			}
			if l.NotAfter > until[l.Endpoint] {
				until[l.Endpoint] = l.NotAfter
			}
		}
		res = LeaveResult{AccountID: a.ID, Slug: a.Slug, Leaves: len(leaves)}
		for ep, na := range until {
			if na > now.Unix() {
				res.Vacated = append(res.Vacated, store.VacatedAddress{Endpoint: ep, Slug: a.Slug, UntilAt: na, At: now.Unix()})
			}
		}
		sort.Slice(res.Vacated, func(i, j int) bool { return res.Vacated[i].Endpoint < res.Vacated[j].Endpoint })
		if held, err = tx.ListBlobs(ctx, accountID); err != nil {
			return err
		}
		for _, v := range res.Vacated {
			if err := tx.UpsertVacatedAddress(ctx, v); err != nil {
				return err
			}
		}
		if _, err := tx.DeleteTokensByAccount(ctx, accountID); err != nil {
			return err
		}
		if _, err := tx.DeleteIdempotencyByAccount(ctx, accountID); err != nil {
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
	// still refers to it.
	for _, b := range held {
		refs, err := m.Store.CountBlobRefs(ctx, b.Hash)
		if err != nil {
			failed = append(failed, err)
			continue
		}
		if refs > 0 || removeBlob == nil {
			continue
		}
		if err := removeBlob(b.Hash); err != nil {
			failed = append(failed, fmt.Errorf("media %s: %w", b.Hash, err))
			continue
		}
		res.BlobsRemoved++
	}
	if len(failed) > 0 {
		return res, fmt.Errorf("identity: leave %s: the records are erased, and %d thing(s) were not finished: %w", res.Slug, len(failed), errors.Join(failed...))
	}
	return res, nil
}
