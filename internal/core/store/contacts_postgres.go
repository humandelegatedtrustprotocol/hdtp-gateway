package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
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
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, RootCert: c.RootCert,
		// What the archive says, and active is always a contact (internal/portable everActiveOf).
		EverActive: importedEverActive(c),
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
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, ChainSentKid: c.ChainSentKid,
		RootCert: c.RootCert, EverActive: everActive(c.Status),
	})
	if err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

func (s *Postgres) GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error) {
	r, err := s.q.GetContact(ctx, pgdb.GetContactParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return Contact{}, err
	}
	return contactFromRow(sqlitedb.Contact(r)), nil
}

func (s *Postgres) ListContacts(ctx context.Context, accountID string) ([]Contact, error) {
	rs, err := s.q.ListContacts(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Contact, 0, len(rs))
	for _, r := range rs {
		out = append(out, contactFromRow(sqlitedb.Contact(r)))
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

func (s *Postgres) MoveContactStatus(ctx context.Context, accountID, fingerprint, from, to string) (bool, error) {
	// Status_2 is the guard: the status the move is from.
	n, err := s.q.MoveContactStatus(ctx, pgdb.MoveContactStatusParams{
		Status: to, AccountID: accountID, Fingerprint: fingerprint, Status_2: from,
	})
	return n == 1, err
}

func (s *Postgres) DeleteContactInStatus(ctx context.Context, accountID, fingerprint, status string) (bool, error) {
	n, err := s.q.DeleteContactInStatus(ctx, pgdb.DeleteContactInStatusParams{
		AccountID: accountID, Fingerprint: fingerprint, Status: status,
	})
	return n == 1, err
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

func (s *Postgres) RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error) {
	var rootCert []byte
	if len(c.RootCert) > 0 {
		rootCert = c.RootCert // nil keeps the certificate the row already holds
	}
	n, err := s.q.RedeemOverPendingContact(ctx, pgdb.RedeemOverPendingContactParams{
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions), InviteID: c.InviteID,
		DisplayName: c.DisplayName, Card: c.Card, Spki: c.SPKI, Endpoint: c.Endpoint, Leaf: c.Leaf,
		RootCert: rootCert, AccountID: c.AccountID, Fingerprint: c.Fingerprint,
	})
	return n > 0, err
}

func (s *Postgres) DeleteExpiredPendingContacts(ctx context.Context, accountID string, cutoff int64) ([]ExpiredContact, error) {
	rows, err := s.q.DeleteExpiredPendingContacts(ctx, pgdb.DeleteExpiredPendingContactsParams{AccountID: accountID, CreatedAt: cutoff})
	if err != nil {
		return nil, err
	}
	out := make([]ExpiredContact, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExpiredContact{Fingerprint: r.Fingerprint, Status: r.Status})
	}
	return out, nil
}
