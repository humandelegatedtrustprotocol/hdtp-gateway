package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
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

// InsertContact inserts a contact, giving it a random id, the current time as CreatedAt, ever_active
// for an active status and a request clock for pending_in and pending_out, and returns the stored
// row.
func (s *SQLite) InsertContact(ctx context.Context, c Contact) (Contact, error) {
	if err := s.q.InsertContact(ctx, contactInsert(&c)); err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

// ImportContact writes a contact that arrived in an export, see ContactStore.ImportContact. It
// refuses a contact with no HandshakeDueAt.
func (s *SQLite) ImportContact(ctx context.Context, c Contact) error {
	p, err := contactImport(c)
	if err != nil {
		return err
	}
	return s.q.ImportContact(ctx, p)
}

// ClearContactHandshake records that an imported contact has been told this host's handshake. A
// contact that is not there is ErrNotFound.
func (s *SQLite) ClearContactHandshake(ctx context.Context, accountID, fingerprint string) error {
	n, err := s.q.ClearContactHandshake(ctx, sqlitedb.ClearContactHandshakeParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetContact returns the contact, or ErrNotFound.
func (s *SQLite) GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error) {
	r, err := s.q.GetContact(ctx, sqlitedb.GetContactParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return Contact{}, err
	}
	return contactFromRow(r), nil
}

// CountContactsByStatus counts one account's contacts in one status, reading those rows alone (held
// by TestCountingContactsByStatusReadsThoseRowsAlone).
func (s *SQLite) CountContactsByStatus(ctx context.Context, accountID, status string) (int64, error) {
	return s.q.CountContactsByStatus(ctx, sqlitedb.CountContactsByStatusParams{AccountID: accountID, Status: status})
}

// ListContacts returns the account's contacts ordered by creation time and id.
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

// PinCandidates returns the contacts a sealed call's proof could concern: the row whose fingerprint
// is root, the rows at endpoint, and the row whose pinned leaf's key fingerprint is leafFingerprint,
// in ListContacts' order. An empty argument matches nothing.
func (s *SQLite) PinCandidates(ctx context.Context, accountID, root, endpoint, leafFingerprint string) ([]Contact, error) {
	rs, err := s.q.PinCandidates(ctx, pinCandidates(accountID, root, endpoint, leafFingerprint))
	if err != nil {
		return nil, err
	}
	out := make([]Contact, 0, len(rs))
	for _, r := range rs {
		out = append(out, contactFromRow(r))
	}
	return out, nil
}

// UpdateContactStatus moves a contact to status whatever its current one; a move to active sets
// EverActive. A contact that is not there is an error. MoveContactStatus is the guarded form.
func (s *SQLite) UpdateContactStatus(ctx context.Context, accountID, fingerprint, status string) error {
	return contactChanged(s.q.UpdateContactStatus(ctx, sqlitedb.UpdateContactStatusParams{
		Status: status, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// MoveContactStatus moves a contact from `from` to `to` only if it is still in `from`, and reports
// whether it moved. A move to active sets EverActive.
func (s *SQLite) MoveContactStatus(ctx context.Context, accountID, fingerprint, from, to string) (bool, error) {
	// Status_2 is the guard: the status the move is from.
	n, err := s.q.MoveContactStatus(ctx, sqlitedb.MoveContactStatusParams{
		Status: to, AccountID: accountID, Fingerprint: fingerprint, Status_2: from,
	})
	return n == 1, err
}

// DeleteContactInStatus removes the contact only while it is still in status, and reports whether it
// did.
func (s *SQLite) DeleteContactInStatus(ctx context.Context, accountID, fingerprint, status string) (bool, error) {
	n, err := s.q.DeleteContactInStatus(ctx, sqlitedb.DeleteContactInStatusParams{
		AccountID: accountID, Fingerprint: fingerprint, Status: status,
	})
	return n == 1, err
}

// UpdateContactPermissions sets what we granted the contact, as a permission list and a preset; a
// contact that is not there is an error.
func (s *SQLite) UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error {
	return contactChanged(s.q.UpdateContactPermissions(ctx, sqlitedb.UpdateContactPermissionsParams{
		Permissions: permsToJSON(permissions), Preset: preset, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// UpdateContactTrust sets the contact's trust flag; a contact that is not there is an error.
func (s *SQLite) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	return contactChanged(s.q.UpdateContactTrust(ctx, sqlitedb.UpdateContactTrustParams{
		TrustFlag: trustFlag, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// DeleteContact removes the contact row entirely; a contact that is not there is an error ("contact
// not found").
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

// UpdateContactCard rewrites a contact's card and display name; a contact that is not there is an
// error. The pinned key does not change here.
func (s *SQLite) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	return contactChanged(s.q.UpdateContactCard(ctx, sqlitedb.UpdateContactCardParams{
		Card: card, DisplayName: displayName, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// RedeemOverPendingContact rewrites a pending_in contact to the status, grant, invite and pin of c,
// see ContactStore.RedeemOverPendingContact. A row that is no longer pending_in is left alone and
// false is returned.
func (s *SQLite) RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error) {
	n, err := s.q.RedeemOverPendingContact(ctx, contactRedeem(c))
	return n > 0, err
}

// DeleteExpiredPendingContacts deletes the account's pending_in and pending_out rows whose request
// clock (RequestedAt) is before cutoff, and returns the fingerprint and status of each.
func (s *SQLite) DeleteExpiredPendingContacts(ctx context.Context, accountID string, cutoff int64) ([]ExpiredContact, error) {
	rows, err := s.q.DeleteExpiredPendingContacts(ctx, sqlitedb.DeleteExpiredPendingContactsParams{AccountID: accountID, RequestedAt: sql.NullInt64{Int64: cutoff, Valid: true}})
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

// ImportContactPin gives a contact held with no leaf the pin an export carries and marks the
// handshake owed, see ContactStore.ImportContactPin. It refuses a contact with no HandshakeDueAt.
func (s *SQLite) ImportContactPin(ctx context.Context, c Contact) (bool, error) {
	p, err := contactPin(c)
	if err != nil {
		return false, err
	}
	n, err := s.q.ImportContactPin(ctx, p)
	return n > 0, err
}

// MarkContactRequested turns a contact in status `from` into a request of ours (pending_out) with
// its request clock set to `at`, leaving EverActive as it was. False when the contact is not in that
// status.
func (s *SQLite) MarkContactRequested(ctx context.Context, accountID, fingerprint, from string, at int64) (bool, error) {
	n, err := s.q.MarkContactRequested(ctx, sqlitedb.MarkContactRequestedParams{
		RequestedAt: nullUnix(at), AccountID: accountID, Fingerprint: fingerprint, Status: from,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

// TakeBackContactRequest returns a contact marked by MarkContactRequested at `markedAt` to status
// `to` with request clock `requestedAt` (0 for none). False when the row is no longer that approach.
func (s *SQLite) TakeBackContactRequest(ctx context.Context, accountID, fingerprint, to string, requestedAt, markedAt int64) (bool, error) {
	n, err := s.q.TakeBackContactRequest(ctx, sqlitedb.TakeBackContactRequestParams{
		Status: to, RequestedAt: nullUnix(requestedAt), AccountID: accountID, Fingerprint: fingerprint, RequestedAt_2: nullUnix(markedAt),
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

// CountHeldContacts counts the account's active contacts and the requests it sent (pending_out);
// pending_in and blocked rows do not count.
func (s *SQLite) CountHeldContacts(ctx context.Context, accountID string) (int64, error) {
	return s.q.CountHeldContacts(ctx, accountID)
}
