package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (s *Postgres) InsertInvite(ctx context.Context, inv Invite) (Invite, error) {
	if inv.ID == "" {
		inv.ID = newID()
	}
	if inv.CreatedAt == 0 {
		inv.CreatedAt = now()
	}
	if inv.MaxUses == 0 {
		inv.MaxUses = 1
	}
	err := s.q.InsertInvite(ctx, pgdb.InsertInviteParams{
		ID: inv.ID, AccountID: inv.AccountID, TokenHash: inv.TokenHash,
		ExpiresAt: inv.ExpiresAt, MaxUses: inv.MaxUses, AutoAccept: b2i(inv.AutoAccept),
		Preset: inv.Preset, Permissions: permsToJSON(inv.Permissions), Label: inv.Label,
		CreatedAt: inv.CreatedAt,
	})
	if err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func pgInvite(r pgdb.Invite) Invite {
	return Invite{
		ID: r.ID, AccountID: r.AccountID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
		MaxUses: r.MaxUses, Uses: r.Uses, AutoAccept: r.AutoAccept != 0, Preset: r.Preset,
		Permissions: permsFromJSON(r.Permissions), Label: r.Label,
		RevokedAt: r.RevokedAt.Int64, CreatedAt: r.CreatedAt,
	}
}

func (s *Postgres) GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHash(ctx, pgdb.GetInviteByHashParams{AccountID: accountID, TokenHash: tokenHash})
	if err != nil {
		return Invite{}, err
	}
	return pgInvite(r), nil
}

func (s *Postgres) GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHashGlobal(ctx, tokenHash)
	if err != nil {
		return Invite{}, err
	}
	return pgInvite(r), nil
}

func (s *Postgres) ListInvites(ctx context.Context, accountID string) ([]Invite, error) {
	rs, err := s.q.ListInvites(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rs))
	for _, r := range rs {
		out = append(out, pgInvite(r))
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
		RevokedAt: pgtype.Int8{Int64: nowTS, Valid: true}, ID: inviteID, AccountID: accountID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: invite missing or already revoked")
	}
	return nil
}
