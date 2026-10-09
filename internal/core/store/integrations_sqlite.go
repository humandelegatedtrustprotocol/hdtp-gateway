package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertIntegration inserts an integration, defaulting its id, status ("disabled"), auth kind
// ("none") and times, and returns it. A slug the account already uses is refused by the table.
func (s *SQLite) InsertIntegration(ctx context.Context, in Integration) (Integration, error) {
	if err := s.q.InsertIntegration(ctx, integrationInsert(&in)); err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return in, nil
}

// GetIntegration returns the account's integration by slug; an error wrapping ErrNotFound when there
// is none.
func (s *SQLite) GetIntegration(ctx context.Context, accountID, slug string) (Integration, error) {
	r, err := s.q.GetIntegration(ctx, sqlitedb.GetIntegrationParams{AccountID: accountID, Slug: slug})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(r), nil
}

// GetIntegrationByID returns the integration by id; an error wrapping ErrNotFound when there is
// none.
func (s *SQLite) GetIntegrationByID(ctx context.Context, id string) (Integration, error) {
	r, err := s.q.GetIntegrationByID(ctx, id)
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(r), nil
}

// GetAccountIntegration returns the account's integration by id; an error wrapping ErrNotFound
// when there is none, and the same error when the id names another account's.
func (s *SQLite) GetAccountIntegration(ctx context.Context, accountID, id string) (Integration, error) {
	r, err := s.q.GetAccountIntegration(ctx, sqlitedb.GetAccountIntegrationParams{AccountID: accountID, ID: id})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(r), nil
}

// ListIntegrations returns the account's integrations ordered by slug.
func (s *SQLite) ListIntegrations(ctx context.Context, accountID string) ([]Integration, error) {
	rows, err := s.q.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]Integration, 0, len(rows))
	for _, r := range rows {
		out = append(out, integrationFromRow(r))
	}
	return out, nil
}

// UpdateIntegrationStatus sets an integration's status and touches its update time; one that is not
// there is an error wrapping ErrNotFound.
func (s *SQLite) UpdateIntegrationStatus(ctx context.Context, id, status string) error {
	n, err := s.q.UpdateIntegrationStatus(ctx, sqlitedb.UpdateIntegrationStatusParams{
		Status: status, UpdatedAt: now(), ID: id,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: integration %s: %w", id, sql.ErrNoRows)
	}
	return nil
}

// UpdateIntegrationConfig rewrites an integration's transport, endpoint, command and auth kind; one
// that is not there is an error wrapping ErrNotFound.
func (s *SQLite) UpdateIntegrationConfig(ctx context.Context, id, transport, endpoint, command, authKind string) error {
	n, err := s.q.UpdateIntegrationConfig(ctx, sqlitedb.UpdateIntegrationConfigParams{
		Transport: transport, Endpoint: endpoint, Command: command,
		AuthKind: authKind, UpdatedAt: now(), ID: id,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: integration %s: %w", id, sql.ErrNoRows)
	}
	return nil
}

// DeleteIntegration deletes the integration by id; one that is not there is an error wrapping
// ErrNotFound.
func (s *SQLite) DeleteIntegration(ctx context.Context, id string) error {
	n, err := s.q.DeleteIntegration(ctx, id)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: integration %s: %w", id, sql.ErrNoRows)
	}
	return nil
}

// SetIntegrationSecret stores the keyring-sealed credential blob of an integration; an integration
// that is not there is an error wrapping ErrNotFound.
func (s *SQLite) SetIntegrationSecret(ctx context.Context, id string, sealed []byte) error {
	n, err := s.q.SetIntegrationSecret(ctx, sqlitedb.SetIntegrationSecretParams{
		Secret: sealed, UpdatedAt: now(), ID: id,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: integration %s: %w", id, sql.ErrNoRows)
	}
	return nil
}

// GetIntegrationSecret returns the integration's keyring-sealed credential blob; an error wrapping
// ErrNotFound when the integration is not there.
func (s *SQLite) GetIntegrationSecret(ctx context.Context, id string) ([]byte, error) {
	b, err := s.q.GetIntegrationSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return b, nil
}

// InsertCatalog stores an immutable catalog snapshot, giving it a random id and the current time
// when it has none, and returns it. A version already taken for the integration is refused by the
// table.
func (s *SQLite) InsertCatalog(ctx context.Context, c Catalog) (Catalog, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	err := s.q.InsertCatalog(ctx, sqlitedb.InsertCatalogParams{
		ID: c.ID, IntegrationID: c.IntegrationID, Version: c.Version,
		Tools: c.Tools, CreatedAt: c.CreatedAt,
	})
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return c, nil
}

// LatestCatalog returns the highest catalog version of an integration; an error wrapping ErrNotFound
// when it has none.
func (s *SQLite) LatestCatalog(ctx context.Context, integrationID string) (Catalog, error) {
	r, err := s.q.LatestCatalog(ctx, integrationID)
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(r), nil
}

// GetCatalog returns one catalog version of an integration; an error wrapping ErrNotFound when there
// is none.
func (s *SQLite) GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error) {
	r, err := s.q.GetCatalog(ctx, sqlitedb.GetCatalogParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(r), nil
}

// InsertExposure stores an immutable exposure set, giving it a random id and the current time when
// it has none, and returns it. A version already taken for the integration is refused by the table.
func (s *SQLite) InsertExposure(ctx context.Context, e Exposure) (Exposure, error) {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.CreatedAt == 0 {
		e.CreatedAt = now()
	}
	err := s.q.InsertExposure(ctx, sqlitedb.InsertExposureParams{
		ID: e.ID, IntegrationID: e.IntegrationID, Version: e.Version,
		CatalogVersion: e.CatalogVersion, Entries: e.Entries, CreatedAt: e.CreatedAt,
	})
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return e, nil
}

// LatestExposure returns the highest exposure version of an integration; an error wrapping
// ErrNotFound when it has none.
func (s *SQLite) LatestExposure(ctx context.Context, integrationID string) (Exposure, error) {
	r, err := s.q.LatestExposure(ctx, integrationID)
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(r), nil
}

// GetExposure returns one exposure version of an integration; an error wrapping ErrNotFound when
// there is none.
func (s *SQLite) GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error) {
	r, err := s.q.GetExposure(ctx, sqlitedb.GetExposureParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(r), nil
}

// PutIdempotency records msg_id's acknowledgment for a conversation once: the first writer wins. It
// returns the stored ack and whether a record already existed; expiresAt 0 writes an undated record.
func (s *SQLite) PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (string, bool, error) {
	exp := sql.NullInt64{Int64: expiresAt, Valid: expiresAt != 0}
	n, err := s.q.InsertIdempotency(ctx, sqlitedb.InsertIdempotencyParams{
		AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
		Ack: ack, CreatedAt: now(), ExpiresAt: exp,
	})
	if err != nil {
		return "", false, fmt.Errorf("store: %w", err)
	}
	stored, err := s.q.GetIdempotency(ctx, sqlitedb.GetIdempotencyParams{
		AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
	})
	if err != nil {
		return "", false, fmt.Errorf("store: %w", err)
	}
	return stored, n == 0, nil
}

// UpdateIdempotencyAck replaces the stored ack of an existing record; one that is not there is an
// error wrapping ErrNotFound.
func (s *SQLite) UpdateIdempotencyAck(ctx context.Context, accountID, contactFpr, msgID, ack string) error {
	n, err := s.q.UpdateIdempotencyAck(ctx, sqlitedb.UpdateIdempotencyAckParams{
		Ack: ack, AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: idempotency %s: %w", msgID, sql.ErrNoRows)
	}
	return nil
}

// InsertPendingRequest inserts a parked agent-answered request as open, defaulting its id, creation
// time and trust flag ("messages_only"), and returns it.
func (s *SQLite) InsertPendingRequest(ctx context.Context, p PendingRequest) (PendingRequest, error) {
	if p.ID == "" {
		p.ID = newID()
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = now()
	}
	if p.TrustFlag == "" {
		p.TrustFlag = "messages_only"
	}
	p.Status = "open"
	err := s.q.InsertPendingRequest(ctx, sqlitedb.InsertPendingRequestParams{
		ID: p.ID, AccountID: p.AccountID, ContactFpr: p.ContactFpr, Capability: p.Capability,
		Args: p.Args, TrustFlag: p.TrustFlag, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
	})
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return p, nil
}

// GetPendingRequest returns the pending request by id, or an error wrapping ErrNotFound. It returns
// the row whatever its status or expiry.
func (s *SQLite) GetPendingRequest(ctx context.Context, id string) (PendingRequest, error) {
	r, err := s.q.GetPendingRequest(ctx, id)
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return pendingFromRow(r), nil
}

// GetAccountPendingRequest returns the account's pending request by id, whatever its status or
// expiry; an error wrapping ErrNotFound when there is none, and the same error when the id names
// another account's.
func (s *SQLite) GetAccountPendingRequest(ctx context.Context, accountID, id string) (PendingRequest, error) {
	r, err := s.q.GetAccountPendingRequest(ctx, sqlitedb.GetAccountPendingRequestParams{AccountID: accountID, ID: id})
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return pendingFromRow(r), nil
}

// ListOpenPendingRequests returns the account's open requests that expire after now, oldest first.
func (s *SQLite) ListOpenPendingRequests(ctx context.Context, accountID string, nowUnix int64) ([]PendingRequest, error) {
	rows, err := s.q.ListOpenPendingRequests(ctx, sqlitedb.ListOpenPendingRequestsParams{
		AccountID: accountID, ExpiresAt: nowUnix,
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]PendingRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, pendingFromRow(r))
	}
	return out, nil
}

// AnswerPendingRequest closes the account's open, unexpired pending request with result, recording
// answeredAt; false when the request is not open, has expired by now, is another account's, or is
// not there. It changes nothing in that case.
func (s *SQLite) AnswerPendingRequest(ctx context.Context, accountID, id, result string, answeredAt, nowUnix int64) (bool, error) {
	n, err := s.q.AnswerPendingRequest(ctx, sqlitedb.AnswerPendingRequestParams{
		Result: result, AnsweredAt: sql.NullInt64{Int64: answeredAt, Valid: true},
		AccountID: accountID, ID: id, ExpiresAt: nowUnix,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}
