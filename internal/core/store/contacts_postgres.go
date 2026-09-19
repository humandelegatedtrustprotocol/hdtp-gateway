package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func (s *Postgres) ImportContact(ctx context.Context, c Contact) error {
	if c.ID == "" {
		c.ID = newID()
	}
	return s.q.ImportContact(ctx, pgdb.ImportContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		TheirPermissions: permsToJSON(c.TheirPermissions), TrustFlag: c.TrustFlag,
		DisplayName: c.DisplayName, Petname: c.Petname, Card: c.Card, CreatedAt: c.CreatedAt,
		PinnedAt: pgtype.Int8{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, RootCert: c.RootCert,
	})
}

func (s *Postgres) InsertContact(ctx context.Context, c Contact) (Contact, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	err := s.q.InsertContact(ctx, pgdb.InsertContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		DisplayName: c.DisplayName, Card: c.Card, CreatedAt: c.CreatedAt, InviteID: c.InviteID,
		PinnedAt: pgtype.Int8{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, ChainSentKid: c.ChainSentKid,
		RootCert: c.RootCert,
	})
	if err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

func pgContact(r pgdb.Contact) Contact {
	return Contact{
		ID: r.ID, AccountID: r.AccountID, Fingerprint: r.Fingerprint, SPKI: r.Spki,
		Status: r.Status, Preset: r.Preset, Permissions: permsFromJSON(r.Permissions),
		TrustFlag: r.TrustFlag, DisplayName: r.DisplayName, Card: r.Card,
		CreatedAt: r.CreatedAt, PinnedAt: r.PinnedAt.Int64,
		// What the peer granted US (PACT §6.2), which every read used to drop.
		TheirPermissions: permsFromJSON(r.TheirPermissions),
		Petname:          r.Petname,
		InviteID:         r.InviteID,
		Endpoint:         r.Endpoint,
		Leaf:             r.Leaf,
		ChainSentKid:     r.ChainSentKid,
		RootCert:         r.RootCert,
	}
}

func (s *Postgres) GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error) {
	r, err := s.q.GetContact(ctx, pgdb.GetContactParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return Contact{}, err
	}
	return pgContact(r), nil
}

func (s *Postgres) ListContacts(ctx context.Context, accountID string) ([]Contact, error) {
	rs, err := s.q.ListContacts(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Contact, 0, len(rs))
	for _, r := range rs {
		out = append(out, pgContact(r))
	}
	return out, nil
}

func (s *Postgres) UpdateContactStatus(ctx context.Context, accountID, fingerprint, status string) error {
	n, err := s.q.UpdateContactStatus(ctx, pgdb.UpdateContactStatusParams{
		Status: status, AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *Postgres) UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error {
	n, err := s.q.UpdateContactPermissions(ctx, pgdb.UpdateContactPermissionsParams{
		Permissions: permsToJSON(permissions), Preset: preset, AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *Postgres) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	n, err := s.q.UpdateContactTrust(ctx, pgdb.UpdateContactTrustParams{
		TrustFlag: trustFlag, AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *Postgres) DeleteContact(ctx context.Context, accountID, fingerprint string) error {
	n, err := s.q.DeleteContact(ctx, pgdb.DeleteContactParams{
		AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

// SetContactPetname records the owner's own name for a contact. It is local:
// nothing about it is sent to the peer, and no peer can change it.
func (s *Postgres) SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error {
	n, err := s.q.UpdateContactPetname(ctx, pgdb.UpdateContactPetnameParams{
		Petname: petname, AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *Postgres) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	n, err := s.q.UpdateContactCard(ctx, pgdb.UpdateContactCardParams{
		Card: card, DisplayName: displayName, AccountID: accountID, Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}
