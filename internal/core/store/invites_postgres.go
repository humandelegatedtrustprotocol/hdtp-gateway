package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func (s *Postgres) InsertInvite(ctx context.Context, inv Invite) (Invite, error) {
	if err := s.q.InsertInvite(ctx, pgdb.InsertInviteParams(inviteInsert(&inv))); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func (s *Postgres) GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHash(ctx, pgdb.GetInviteByHashParams{AccountID: accountID, TokenHash: tokenHash})
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(sqlitedb.Invite(r)), nil
}

func (s *Postgres) GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHashGlobal(ctx, tokenHash)
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(sqlitedb.Invite(r)), nil
}

func (s *Postgres) ListInvites(ctx context.Context, accountID string) ([]Invite, error) {
	rs, err := s.q.ListInvites(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rs))
	for _, r := range rs {
		out = append(out, inviteFromRow(sqlitedb.Invite(r)))
	}
	return out, nil
}

func (s *Postgres) ConsumeInviteUse(ctx context.Context, inviteID string, nowTS int64) (bool, error) {
	n, err := s.q.ConsumeInviteUse(ctx, pgdb.ConsumeInviteUseParams{ID: inviteID, ExpiresAt: nowTS})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Postgres) RevokeInvite(ctx context.Context, accountID, inviteID string, nowTS int64) error {
	n, err := s.q.RevokeInvite(ctx, pgdb.RevokeInviteParams{
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
