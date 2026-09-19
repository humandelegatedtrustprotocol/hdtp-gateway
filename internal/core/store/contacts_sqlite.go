package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

func permsToJSON(perms []string) string {
	if perms == nil {
		perms = []string{}
	}
	b, _ := json.Marshal(perms)
	return string(b)
}

func permsFromJSON(raw string) []string {
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []string{}
	}
	return out
}

func (s *SQLite) InsertContact(ctx context.Context, c Contact) (Contact, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	err := s.q.InsertContact(ctx, sqlitedb.InsertContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		DisplayName: c.DisplayName, Card: c.Card, CreatedAt: c.CreatedAt, InviteID: c.InviteID,
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, ChainSentKid: c.ChainSentKid,
		RootCert: c.RootCert,
	})
	if err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

func (s *SQLite) ImportContact(ctx context.Context, c Contact) error {
	if c.ID == "" {
		c.ID = newID()
	}
	return s.q.ImportContact(ctx, sqlitedb.ImportContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		TheirPermissions: permsToJSON(c.TheirPermissions), TrustFlag: c.TrustFlag,
		DisplayName: c.DisplayName, Petname: c.Petname, Card: c.Card, CreatedAt: c.CreatedAt,
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, RootCert: c.RootCert,
	})
}

func contactFromRow(r sqlitedb.Contact) Contact {
	return Contact{
		ID: r.ID, AccountID: r.AccountID, Fingerprint: r.Fingerprint, SPKI: r.Spki,
		Status: r.Status, Preset: r.Preset, Permissions: permsFromJSON(r.Permissions),
		TrustFlag: r.TrustFlag, DisplayName: r.DisplayName, Card: r.Card,
		CreatedAt: r.CreatedAt, PinnedAt: r.PinnedAt.Int64,
		// What the peer granted US (PACT §6.2). The column and its writer both
		// existed; nothing read it back, so the value was write-only.
		TheirPermissions: permsFromJSON(r.TheirPermissions),
		Petname:          r.Petname,
		InviteID:         r.InviteID,
		Endpoint:         r.Endpoint,
		Leaf:             r.Leaf,
		ChainSentKid:     r.ChainSentKid,
		RootCert:         r.RootCert,
	}
}

func (s *SQLite) GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error) {
	r, err := s.q.GetContact(ctx, sqlitedb.GetContactParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return Contact{}, err
	}
	return contactFromRow(r), nil
}

func (s *SQLite) ListContacts(ctx context.Context, accountID string) ([]Contact, error) {
	rs, err := s.q.ListContacts(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Contact, 0, len(rs))
	for _, r := range rs {
		out = append(out, contactFromRow(r))
	}
	return out, nil
}

func (s *SQLite) UpdateContactStatus(ctx context.Context, accountID, fingerprint, status string) error {
	n, err := s.q.UpdateContactStatus(ctx, sqlitedb.UpdateContactStatusParams{
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

func (s *SQLite) UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error {
	n, err := s.q.UpdateContactPermissions(ctx, sqlitedb.UpdateContactPermissionsParams{
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

func (s *SQLite) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	n, err := s.q.UpdateContactTrust(ctx, sqlitedb.UpdateContactTrustParams{
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

func (s *SQLite) DeleteContact(ctx context.Context, accountID, fingerprint string) error {
	n, err := s.q.DeleteContact(ctx, sqlitedb.DeleteContactParams{
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
func (s *SQLite) SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error {
	n, err := s.q.UpdateContactPetname(ctx, sqlitedb.UpdateContactPetnameParams{
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

func (s *SQLite) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	n, err := s.q.UpdateContactCard(ctx, sqlitedb.UpdateContactCardParams{
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
