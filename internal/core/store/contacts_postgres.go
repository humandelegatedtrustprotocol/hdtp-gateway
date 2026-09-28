package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pact-cloud/pact-gateway/internal/core/store/pgdb"
	"github.com/pact-cloud/pact-gateway/internal/core/store/sqlitedb"
)

func (s *Postgres) ImportContact(ctx context.Context, c Contact) error {
	p, err := contactImport(c)
	if err != nil {
		return err
	}
	return s.q.ImportContact(ctx, pgdb.ImportContactParams(p))
}

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

func (s *Postgres) InsertContact(ctx context.Context, c Contact) (Contact, error) {
	if err := s.q.InsertContact(ctx, pgdb.InsertContactParams(contactInsert(&c))); err != nil {
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

func (s *Postgres) CountContactsByStatus(ctx context.Context, accountID, status string) (int64, error) {
	return s.q.CountContactsByStatus(ctx, pgdb.CountContactsByStatusParams{AccountID: accountID, Status: status})
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
	return contactChanged(s.q.UpdateContactStatus(ctx, pgdb.UpdateContactStatusParams{
		Status: status, AccountID: accountID, Fingerprint: fingerprint,
	}))
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
	return contactChanged(s.q.UpdateContactPermissions(ctx, pgdb.UpdateContactPermissionsParams{
		Permissions: permsToJSON(permissions), Preset: preset, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *Postgres) UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error {
	return contactChanged(s.q.UpdateContactTrust(ctx, pgdb.UpdateContactTrustParams{
		TrustFlag: trustFlag, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

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

func (s *Postgres) UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error {
	return contactChanged(s.q.UpdateContactCard(ctx, pgdb.UpdateContactCardParams{
		Card: card, DisplayName: displayName, AccountID: accountID, Fingerprint: fingerprint,
	}))
}

func (s *Postgres) RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error) {
	n, err := s.q.RedeemOverPendingContact(ctx, pgdb.RedeemOverPendingContactParams(contactRedeem(c)))
	return n > 0, err
}

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

func (s *Postgres) ImportContactPin(ctx context.Context, c Contact) (bool, error) {
	p, err := contactPin(c)
	if err != nil {
		return false, err
	}
	n, err := s.q.ImportContactPin(ctx, pgdb.ImportContactPinParams(p))
	return n > 0, err
}

func (s *Postgres) MarkContactRequested(ctx context.Context, accountID, fingerprint, from string, at int64) (bool, error) {
	n, err := s.q.MarkContactRequested(ctx, pgdb.MarkContactRequestedParams{
		RequestedAt: nullUnix(at), AccountID: accountID, Fingerprint: fingerprint, Status: from,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

func (s *Postgres) TakeBackContactRequest(ctx context.Context, accountID, fingerprint, to string, requestedAt, markedAt int64) (bool, error) {
	n, err := s.q.TakeBackContactRequest(ctx, pgdb.TakeBackContactRequestParams{
		Status: to, RequestedAt: nullUnix(requestedAt), AccountID: accountID, Fingerprint: fingerprint, RequestedAt_2: nullUnix(markedAt),
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}
