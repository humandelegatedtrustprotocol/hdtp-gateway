package store

import (
	"context"
	"encoding/json"

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
	if err := s.q.InsertContact(ctx, contactInsert(&c)); err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

func (s *SQLite) ImportContact(ctx context.Context, c Contact) error {
	return s.q.ImportContact(ctx, contactImport(c))
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
	return contactChanged(s.q.UpdateContactStatus(ctx, sqlitedb.UpdateContactStatusParams{
		Status: status, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *SQLite) MoveContactStatus(ctx context.Context, accountID, fingerprint, from, to string) (bool, error) {
	// Status_2 is the guard: the status the move is from.
	n, err := s.q.MoveContactStatus(ctx, sqlitedb.MoveContactStatusParams{
		Status: to, AccountID: accountID, Fingerprint: fingerprint, Status_2: from,
	})
	return n == 1, err
}

func (s *SQLite) DeleteContactInStatus(ctx context.Context, accountID, fingerprint, status string) (bool, error) {
	n, err := s.q.DeleteContactInStatus(ctx, sqlitedb.DeleteContactInStatusParams{
		AccountID: accountID, Fingerprint: fingerprint, Status: status,
	})
	return n == 1, err
}

func (s *SQLite) UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error {
	return contactChanged(s.q.UpdateContactPermissions(ctx, sqlitedb.UpdateContactPermissionsParams{
		Permissions: permsToJSON(permissions), Preset: preset, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *SQLite) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	return contactChanged(s.q.UpdateContactTrust(ctx, sqlitedb.UpdateContactTrustParams{
		TrustFlag: trustFlag, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *SQLite) DeleteContact(ctx context.Context, accountID, fingerprint string) error {
	return contactChanged(s.q.DeleteContact(ctx, sqlitedb.DeleteContactParams{
		AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// SetContactPetname records the owner's own name for a contact. It is local:
// nothing about it is sent to the peer, and no peer can change it.
func (s *SQLite) SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error {
	return contactChanged(s.q.UpdateContactPetname(ctx, sqlitedb.UpdateContactPetnameParams{
		Petname: petname, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *SQLite) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	return contactChanged(s.q.UpdateContactCard(ctx, sqlitedb.UpdateContactCardParams{
		Card: card, DisplayName: displayName, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *SQLite) RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error) {
	n, err := s.q.RedeemOverPendingContact(ctx, contactRedeem(c))
	return n > 0, err
}

func (s *SQLite) DeleteExpiredPendingContacts(ctx context.Context, accountID string, cutoff int64) ([]ExpiredContact, error) {
	rows, err := s.q.DeleteExpiredPendingContacts(ctx, sqlitedb.DeleteExpiredPendingContactsParams{AccountID: accountID, CreatedAt: cutoff})
	if err != nil {
		return nil, err
	}
	out := make([]ExpiredContact, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExpiredContact{Fingerprint: r.Fingerprint, Status: r.Status})
	}
	return out, nil
}

// importedEverActive is the ever_active an imported row is written with: what the archive said,
// and always 1 for an active row.
func importedEverActive(c Contact) int64 {
	if c.EverActive {
		return 1
	}
	return everActive(c.Status)
}

// everActive is the ever_active value a row written with this status starts with.
func everActive(status string) int64 {
	if status == "active" {
		return 1
	}
	return 0
}
