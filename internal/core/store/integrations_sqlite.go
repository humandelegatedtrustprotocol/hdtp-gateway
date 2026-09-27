package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) InsertIntegration(ctx context.Context, in Integration) (Integration, error) {
	if in.ID == "" {
		in.ID = newID()
	}
	if in.Status == "" {
		in.Status = "disabled"
	}
	if in.AuthKind == "" {
		in.AuthKind = "none"
	}
	if in.CreatedAt == 0 {
		in.CreatedAt = now()
	}
	in.UpdatedAt = in.CreatedAt
	err := s.q.InsertIntegration(ctx, sqlitedb.InsertIntegrationParams{
		ID: in.ID, AccountID: in.AccountID, Slug: in.Slug, Transport: in.Transport,
		Endpoint: in.Endpoint, Command: in.Command, AuthKind: in.AuthKind,
		Status: in.Status, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return in, nil
}

func (s *SQLite) GetIntegration(ctx context.Context, accountID, slug string) (Integration, error) {
	r, err := s.q.GetIntegration(ctx, sqlitedb.GetIntegrationParams{AccountID: accountID, Slug: slug})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(r), nil
}

func (s *SQLite) GetIntegrationByID(ctx context.Context, id string) (Integration, error) {
	r, err := s.q.GetIntegrationByID(ctx, id)
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromRow(r), nil
}

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

func (s *SQLite) GetIntegrationSecret(ctx context.Context, id string) ([]byte, error) {
	b, err := s.q.GetIntegrationSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return b, nil
}

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

func (s *SQLite) LatestCatalog(ctx context.Context, integrationID string) (Catalog, error) {
	r, err := s.q.LatestCatalog(ctx, integrationID)
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(r), nil
}

func (s *SQLite) GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error) {
	r, err := s.q.GetCatalog(ctx, sqlitedb.GetCatalogParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromRow(r), nil
}

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

func (s *SQLite) LatestExposure(ctx context.Context, integrationID string) (Exposure, error) {
	r, err := s.q.LatestExposure(ctx, integrationID)
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(r), nil
}

func (s *SQLite) GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error) {
	r, err := s.q.GetExposure(ctx, sqlitedb.GetExposureParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromRow(r), nil
}

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

func (s *SQLite) GetPendingRequest(ctx context.Context, id string) (PendingRequest, error) {
	r, err := s.q.GetPendingRequest(ctx, id)
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return pendingFromRow(r), nil
}

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

func (s *SQLite) AnswerPendingRequest(ctx context.Context, id, result string, answeredAt, nowUnix int64) (bool, error) {
	n, err := s.q.AnswerPendingRequest(ctx, sqlitedb.AnswerPendingRequestParams{
		Result: result, AnsweredAt: sql.NullInt64{Int64: answeredAt, Valid: true},
		ID: id, ExpiresAt: nowUnix,
	})
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}
