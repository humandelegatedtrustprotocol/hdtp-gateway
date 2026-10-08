package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertIntegration inserts an integration, defaulting its id, status ("disabled"), auth kind
// ("none") and times, and returns it. A slug the account already uses is refused by the table.
func (s *Postgres) InsertIntegration(ctx context.Context, in Integration) (Integration, error) {
	if err := s.q.InsertIntegration(ctx, pgdb.InsertIntegrationParams(integrationInsert(&in))); err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return in, nil
}

// GetIntegration returns the account's integration by slug; an error wrapping ErrNotFound when there
// is none.
func (s *Postgres) GetIntegration(ctx context.Context, accountID, slug string) (Integration, error) {
	r, err := s.q.GetIntegration(ctx, pgdb.GetIntegrationParams{AccountID: accountID, Slug: slug})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(sqlitedb.Integration(r)), nil
}

// GetIntegrationByID returns the integration by id; an error wrapping ErrNotFound when there is
// none.
func (s *Postgres) GetIntegrationByID(ctx context.Context, id string) (Integration, error) {
	r, err := s.q.GetIntegrationByID(ctx, id)
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(sqlitedb.Integration(r)), nil
}

// ListIntegrations returns the account's integrations ordered by slug.
func (s *Postgres) ListIntegrations(ctx context.Context, accountID string) ([]Integration, error) {
	rows, err := s.q.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]Integration, 0, len(rows))
	for _, r := range rows {
		out = append(out, integrationFromRow(sqlitedb.Integration(r)))
	}
	return out, nil
}

// UpdateIntegrationStatus sets an integration's status and touches its update time; one that is not
// there is an error wrapping ErrNotFound.
func (s *Postgres) UpdateIntegrationStatus(ctx context.Context, id, status string) error {
	n, err := s.q.UpdateIntegrationStatus(ctx, pgdb.UpdateIntegrationStatusParams{
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
func (s *Postgres) UpdateIntegrationConfig(ctx context.Context, id, transport, endpoint, command, authKind string) error {
	n, err := s.q.UpdateIntegrationConfig(ctx, pgdb.UpdateIntegrationConfigParams{
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
func (s *Postgres) DeleteIntegration(ctx context.Context, id string) error {
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
func (s *Postgres) SetIntegrationSecret(ctx context.Context, id string, sealed []byte) error {
	n, err := s.q.SetIntegrationSecret(ctx, pgdb.SetIntegrationSecretParams{
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
func (s *Postgres) GetIntegrationSecret(ctx context.Context, id string) ([]byte, error) {
	b, err := s.q.GetIntegrationSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return b, nil
}

// InsertCatalog stores an immutable catalog snapshot, giving it a random id and the current time
// when it has none, and returns it. A version already taken for the integration is refused by the
// table.
func (s *Postgres) InsertCatalog(ctx context.Context, c Catalog) (Catalog, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	err := s.q.InsertCatalog(ctx, pgdb.InsertCatalogParams{
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
func (s *Postgres) LatestCatalog(ctx context.Context, integrationID string) (Catalog, error) {
	r, err := s.q.LatestCatalog(ctx, integrationID)
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(sqlitedb.Catalog(r)), nil
}

// GetCatalog returns one catalog version of an integration; an error wrapping ErrNotFound when there
// is none.
func (s *Postgres) GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error) {
	r, err := s.q.GetCatalog(ctx, pgdb.GetCatalogParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(sqlitedb.Catalog(r)), nil
}

// InsertExposure stores an immutable exposure set, giving it a random id and the current time when
// it has none, and returns it. A version already taken for the integration is refused by the table.
func (s *Postgres) InsertExposure(ctx context.Context, e Exposure) (Exposure, error) {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.CreatedAt == 0 {
		e.CreatedAt = now()
	}
	err := s.q.InsertExposure(ctx, pgdb.InsertExposureParams{
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
func (s *Postgres) LatestExposure(ctx context.Context, integrationID string) (Exposure, error) {
	r, err := s.q.LatestExposure(ctx, integrationID)
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(sqlitedb.Exposure(r)), nil
}

// GetExposure returns one exposure version of an integration; an error wrapping ErrNotFound when
// there is none.
func (s *Postgres) GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error) {
	r, err := s.q.GetExposure(ctx, pgdb.GetExposureParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(sqlitedb.Exposure(r)), nil
}

// PutIdempotency records msg_id's acknowledgment for a conversation once: the first writer wins. It
// returns the stored ack and whether a record already existed; expiresAt 0 writes an undated record.
func (s *Postgres) PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (string, bool, error) {
	exp := sql.NullInt64{Int64: expiresAt, Valid: expiresAt != 0}
	n, err := s.q.InsertIdempotency(ctx, pgdb.InsertIdempotencyParams{
		AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
		Ack: ack, CreatedAt: now(), ExpiresAt: exp,
	})
	if err != nil {
		return "", false, fmt.Errorf("store: %w", err)
	}
	stored, err := s.q.GetIdempotency(ctx, pgdb.GetIdempotencyParams{
		AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
	})
	if err != nil {
		return "", false, fmt.Errorf("store: %w", err)
	}
	return stored, n == 0, nil
}

// UpdateIdempotencyAck replaces the stored ack of an existing record; one that is not there is an
// error wrapping ErrNotFound.
func (s *Postgres) UpdateIdempotencyAck(ctx context.Context, accountID, contactFpr, msgID, ack string) error {
	n, err := s.q.UpdateIdempotencyAck(ctx, pgdb.UpdateIdempotencyAckParams{
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
func (s *Postgres) InsertPendingRequest(ctx context.Context, p PendingRequest) (PendingRequest, error) {
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
	err := s.q.InsertPendingRequest(ctx, pgdb.InsertPendingRequestParams{
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
func (s *Postgres) GetPendingRequest(ctx context.Context, id string) (PendingRequest, error) {
	r, err := s.q.GetPendingRequest(ctx, id)
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return pendingFromRow(sqlitedb.PendingRequest(r)), nil
}

// ListOpenPendingRequests returns the account's open requests that expire after now, oldest first.
func (s *Postgres) ListOpenPendingRequests(ctx context.Context, accountID string, nowUnix int64) ([]PendingRequest, error) {
	rows, err := s.q.ListOpenPendingRequests(ctx, pgdb.ListOpenPendingRequestsParams{
		AccountID: accountID, ExpiresAt: nowUnix,
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]PendingRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, pendingFromRow(sqlitedb.PendingRequest(r)))
	}
	return out, nil
}

// AnswerPendingRequest closes an open, unexpired pending request with result, recording answeredAt;
// false when the request is not open, has expired by now, or is not there. It changes nothing in
// that case.
func (s *Postgres) AnswerPendingRequest(ctx context.Context, id, result string, answeredAt, nowUnix int64) (bool, error) {
	n, err := s.q.AnswerPendingRequest(ctx, pgdb.AnswerPendingRequestParams{
		Result: result, AnsweredAt: sql.NullInt64{Int64: answeredAt, Valid: true},
		ID: id, ExpiresAt: nowUnix,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}
