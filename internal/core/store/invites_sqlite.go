package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (s *SQLite) InsertInvite(ctx context.Context, inv Invite) (Invite, error) {
	if inv.ID == "" {
		inv.ID = newID()
	}
	if inv.CreatedAt == 0 {
		inv.CreatedAt = now()
	}
	if inv.MaxUses == 0 {
		inv.MaxUses = 1
	}
	err := s.q.InsertInvite(ctx, sqlitedb.InsertInviteParams{
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

func inviteFromRow(r sqlitedb.Invite) Invite {
	return Invite{
		ID: r.ID, AccountID: r.AccountID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
		MaxUses: r.MaxUses, Uses: r.Uses, AutoAccept: r.AutoAccept != 0, Preset: r.Preset,
		Permissions: permsFromJSON(r.Permissions), Label: r.Label,
		RevokedAt: r.RevokedAt.Int64, CreatedAt: r.CreatedAt,
	}
}

func (s *SQLite) GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHash(ctx, sqlitedb.GetInviteByHashParams{AccountID: accountID, TokenHash: tokenHash})
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(r), nil
}

func (s *SQLite) GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error) {
	r, err := s.q.GetInviteByHashGlobal(ctx, tokenHash)
	if err != nil {
		return Invite{}, err
	}
	return inviteFromRow(r), nil
}

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

func (s *SQLite) ConsumeInviteUse(ctx context.Context, inviteID string, nowTS int64) (bool, error) {
	n, err := s.q.ConsumeInviteUse(ctx, sqlitedb.ConsumeInviteUseParams{ID: inviteID, ExpiresAt: nowTS})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *SQLite) RevokeInvite(ctx context.Context, inviteID string, nowTS int64) error {
	n, err := s.q.RevokeInvite(ctx, sqlitedb.RevokeInviteParams{
		RevokedAt: sql.NullInt64{Int64: nowTS, Valid: true}, ID: inviteID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: invite missing or already revoked")
	}
	return nil
}

func (s *SQLite) RepinContact(ctx context.Context, accountID, oldFpr, newFpr string, newSPKI []byte, card string, nowTS int64) error {
	n, err := s.q.UpdateContactRepin(ctx, sqlitedb.UpdateContactRepinParams{
		Fingerprint: newFpr, Spki: newSPKI, Card: card,
		PinnedAt: sql.NullInt64{Int64: nowTS, Valid: true}, AccountID: accountID, Fingerprint_2: oldFpr,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found for repin")
	}
	return nil
}
