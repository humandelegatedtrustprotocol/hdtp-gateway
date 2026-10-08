package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// InsertInvite inserts an invite, defaulting its id, creation time and a MaxUses of zero to one, and
// returns it.
func (s *SQLite) InsertInvite(ctx context.Context, inv Invite) (Invite, error) {
	if err := s.q.InsertInvite(ctx, inviteInsert(&inv)); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// GetInviteByHash returns the account's invite whose token hash is tokenHash, or ErrNotFound. It
// does not look at expiry, revocation or uses.
func (s *SQLite) GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHash(ctx, sqlitedb.GetInviteByHashParams{AccountID: accountID, TokenHash: tokenHash})
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(r), nil
}

// GetInviteByHashGlobal returns the invite whose token hash is tokenHash across every account, for a
// landing page that carries only the token; ErrNotFound when none. It does not look at expiry,
// revocation or uses.
func (s *SQLite) GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHashGlobal(ctx, tokenHash)
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(r), nil
}

// ListInvites returns the account's invites, oldest first.
func (s *SQLite) ListInvites(ctx context.Context, accountID string) ([]Invite, error) {
	rs, err := s.q.ListInvites(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rs))
	for _, r := range rs {
		out = append(out, inviteFromRow(r))
	}
	return out, nil
}

// ConsumeInviteUse adds one use to the invite and reports true, only while the invite is not
// revoked, has uses left (uses < max_uses) and expires after now. False, with nothing changed,
// otherwise.
func (s *SQLite) ConsumeInviteUse(ctx context.Context, inviteID string, nowTS int64) (bool, error) {
	n, err := s.q.ConsumeInviteUse(ctx, sqlitedb.ConsumeInviteUseParams{ID: inviteID, ExpiresAt: nowTS})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// RevokeInvite revokes one of this account's invites; an invite that is not this account's, or is
// already revoked, is an error wrapping ErrNotFound.
func (s *SQLite) RevokeInvite(ctx context.Context, accountID, inviteID string, nowTS int64) error {
	n, err := s.q.RevokeInvite(ctx, sqlitedb.RevokeInviteParams{
		RevokedAt: sql.NullInt64{Int64: nowTS, Valid: true}, ID: inviteID, AccountID: accountID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: invite missing or already revoked", ErrNotFound)
	}
	return nil
}
