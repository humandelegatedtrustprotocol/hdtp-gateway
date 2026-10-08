package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// ImportContact writes a contact that arrived in an export, see ContactStore.ImportContact. It
// refuses a contact with no HandshakeDueAt.
func (s *Postgres) ImportContact(ctx context.Context, c Contact) error {
	p, err := contactImport(c)
	if err != nil {
		return err
	}
	return s.q.ImportContact(ctx, pgdb.ImportContactParams(p))
}

// ClearContactHandshake records that an imported contact has been told this host's handshake. A
// contact that is not there is ErrNotFound.
func (s *Postgres) ClearContactHandshake(ctx context.Context, accountID, fingerprint string) error {
	n, err := s.q.ClearContactHandshake(ctx, pgdb.ClearContactHandshakeParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// InsertContact inserts a contact, giving it a random id, the current time as CreatedAt, ever_active
// for an active status and a request clock for pending_in and pending_out, and returns the stored
// row.
func (s *Postgres) InsertContact(ctx context.Context, c Contact) (Contact, error) {
	if err := s.q.InsertContact(ctx, pgdb.InsertContactParams(contactInsert(&c))); err != nil {
		return Contact{}, err
	}
	return s.GetContact(ctx, c.AccountID, c.Fingerprint)
}

// GetContact returns the contact, or ErrNotFound.
func (s *Postgres) GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error) {
	r, err := s.q.GetContact(ctx, pgdb.GetContactParams{AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return Contact{}, err
	}
	return contactFromRow(sqlitedb.Contact(r)), nil
}

// CountContactsByStatus counts one account's contacts in one status, reading those rows alone (held
// by TestCountingContactsByStatusReadsThoseRowsAlone).
func (s *Postgres) CountContactsByStatus(ctx context.Context, accountID, status string) (int64, error) {
	return s.q.CountContactsByStatus(ctx, pgdb.CountContactsByStatusParams{AccountID: accountID, Status: status})
}

// ListContacts returns the account's contacts ordered by creation time and id.
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

// PinCandidates returns the contacts a sealed call's proof could concern: the row whose fingerprint
// is root, the rows at endpoint, and the row whose pinned leaf's key fingerprint is leafFingerprint,
// in ListContacts' order. An empty argument matches nothing.
func (s *Postgres) PinCandidates(ctx context.Context, accountID, root, endpoint, leafFingerprint string) ([]Contact, error) {
	rs, err := s.q.PinCandidates(ctx, pgdb.PinCandidatesParams(pinCandidates(accountID, root, endpoint, leafFingerprint)))
	if err != nil {
		return nil, err
	}
	out := make([]Contact, 0, len(rs))
	for _, r := range rs {
		out = append(out, contactFromRow(sqlitedb.Contact(r)))
	}
	return out, nil
}

// UpdateContactStatus moves a contact to status whatever its current one; a move to active sets
// EverActive. A contact that is not there is an error. MoveContactStatus is the guarded form.
func (s *Postgres) UpdateContactStatus(ctx context.Context, accountID, fingerprint, status string) error {
	return contactChanged(s.q.UpdateContactStatus(ctx, pgdb.UpdateContactStatusParams{
		Status: status, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// MoveContactStatus moves a contact from `from` to `to` only if it is still in `from`, and reports
// whether it moved. A move to active sets EverActive.
func (s *Postgres) MoveContactStatus(ctx context.Context, accountID, fingerprint, from, to string) (bool, error) {
	// Status_2 is the guard: the status the move is from.
	n, err := s.q.MoveContactStatus(ctx, pgdb.MoveContactStatusParams{
		Status: to, AccountID: accountID, Fingerprint: fingerprint, Status_2: from,
	})
	return n == 1, err
}

// DeleteContactInStatus removes the contact only while it is still in status, and reports whether it
// did.
func (s *Postgres) DeleteContactInStatus(ctx context.Context, accountID, fingerprint, status string) (bool, error) {
	n, err := s.q.DeleteContactInStatus(ctx, pgdb.DeleteContactInStatusParams{
		AccountID: accountID, Fingerprint: fingerprint, Status: status,
	})
	return n == 1, err
}

// UpdateContactPermissions sets what we granted the contact, as a permission list and a preset; a
// contact that is not there is an error.
func (s *Postgres) UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error {
	return contactChanged(s.q.UpdateContactPermissions(ctx, pgdb.UpdateContactPermissionsParams{
		Permissions: permsToJSON(permissions), Preset: preset, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// UpdateContactTrust sets the contact's trust flag; a contact that is not there is an error.
func (s *Postgres) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	return contactChanged(s.q.UpdateContactTrust(ctx, pgdb.UpdateContactTrustParams{
		TrustFlag: trustFlag, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// DeleteContact removes the contact row entirely; a contact that is not there is an error ("contact
// not found").
func (s *Postgres) DeleteContact(ctx context.Context, accountID, fingerprint string) error {
	return contactChanged(s.q.DeleteContact(ctx, pgdb.DeleteContactParams{
		AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// SetContactPetname records the owner's own name for a contact. It is local:
// nothing about it is sent to the peer, and no peer can change it.
func (s *Postgres) SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error {
	return contactChanged(s.q.UpdateContactPetname(ctx, pgdb.UpdateContactPetnameParams{
		Petname: petname, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// UpdateContactCard rewrites a contact's card and display name; a contact that is not there is an
// error. The pinned key does not change here.
func (s *Postgres) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	return contactChanged(s.q.UpdateContactCard(ctx, pgdb.UpdateContactCardParams{
		Card: card, DisplayName: displayName, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

// RedeemOverPendingContact rewrites a pending_in contact to the status, grant, invite and pin of c,
// see ContactStore.RedeemOverPendingContact. A row that is no longer pending_in is left alone and
// false is returned.
func (s *Postgres) RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error) {
	n, err := s.q.RedeemOverPendingContact(ctx, pgdb.RedeemOverPendingContactParams(contactRedeem(c)))
	return n > 0, err
}

// DeleteExpiredPendingContacts deletes the account's pending_in and pending_out rows whose request
// clock (RequestedAt) is before cutoff, and returns the fingerprint and status of each.
func (s *Postgres) DeleteExpiredPendingContacts(ctx context.Context, accountID string, cutoff int64) ([]ExpiredContact, error) {
	rows, err := s.q.DeleteExpiredPendingContacts(ctx, pgdb.DeleteExpiredPendingContactsParams{AccountID: accountID, RequestedAt: sql.NullInt64{Int64: cutoff, Valid: true}})
	if err != nil {
		return nil, err
	}
	out := make([]ExpiredContact, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExpiredContact{Fingerprint: r.Fingerprint, Status: r.Status})
	}
	return out, nil
}

// ImportContactPin gives a contact held with no leaf the pin an export carries and marks the
// handshake owed, see ContactStore.ImportContactPin. It refuses a contact with no HandshakeDueAt.
func (s *Postgres) ImportContactPin(ctx context.Context, c Contact) (bool, error) {
	p, err := contactPin(c)
	if err != nil {
		return false, err
	}
	n, err := s.q.ImportContactPin(ctx, pgdb.ImportContactPinParams(p))
	return n > 0, err
}

// MarkContactRequested turns a contact in status `from` into a request of ours (pending_out) with
// its request clock set to `at`, leaving EverActive as it was. False when the contact is not in that
// status.
func (s *Postgres) MarkContactRequested(ctx context.Context, accountID, fingerprint, from string, at int64) (bool, error) {
	n, err := s.q.MarkContactRequested(ctx, pgdb.MarkContactRequestedParams{
		RequestedAt: nullUnix(at), AccountID: accountID, Fingerprint: fingerprint, Status: from,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

// TakeBackContactRequest returns a contact marked by MarkContactRequested at `markedAt` to status
// `to` with request clock `requestedAt` (0 for none). False when the row is no longer that approach.
func (s *Postgres) TakeBackContactRequest(ctx context.Context, accountID, fingerprint, to string, requestedAt, markedAt int64) (bool, error) {
	n, err := s.q.TakeBackContactRequest(ctx, pgdb.TakeBackContactRequestParams{
		Status: to, RequestedAt: nullUnix(requestedAt), AccountID: accountID, Fingerprint: fingerprint, RequestedAt_2: nullUnix(markedAt),
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

// CountHeldContacts counts the account's active contacts and the requests it sent (pending_out);
// pending_in and blocked rows do not count.
func (s *Postgres) CountHeldContacts(ctx context.Context, accountID string) (int64, error) {
	return s.q.CountHeldContacts(ctx, accountID)
}
