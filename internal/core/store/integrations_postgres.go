package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
)

func integrationFromPG(r pgdb.Integration) Integration {
	return Integration{
		ID: r.ID, AccountID: r.AccountID, Slug: r.Slug, Transport: r.Transport,
		Endpoint: r.Endpoint, Command: r.Command, AuthKind: r.AuthKind,
		Status: r.Status, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func (s *Postgres) InsertIntegration(ctx context.Context, in Integration) (Integration, error) {
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
	err := s.q.InsertIntegration(ctx, pgdb.InsertIntegrationParams{
		ID: in.ID, AccountID: in.AccountID, Slug: in.Slug, Transport: in.Transport,
		Endpoint: in.Endpoint, Command: in.Command, AuthKind: in.AuthKind,
		Status: in.Status, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return in, nil
}

func (s *Postgres) GetIntegration(ctx context.Context, accountID, slug string) (Integration, error) {
	r, err := s.q.GetIntegration(ctx, pgdb.GetIntegrationParams{AccountID: accountID, Slug: slug})
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromPG(r), nil
}

func (s *Postgres) GetIntegrationByID(ctx context.Context, id string) (Integration, error) {
	r, err := s.q.GetIntegrationByID(ctx, id)
	if err != nil {
		return Integration{}, fmt.Errorf("store: %w", err)
	}
	return integrationFromPG(r), nil
}

func (s *Postgres) ListIntegrations(ctx context.Context, accountID string) ([]Integration, error) {
	rows, err := s.q.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]Integration, 0, len(rows))
	for _, r := range rows {
		out = append(out, integrationFromPG(r))
	}
	return out, nil
}

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

func (s *Postgres) GetIntegrationSecret(ctx context.Context, id string) ([]byte, error) {
	b, err := s.q.GetIntegrationSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return b, nil
}

func catalogFromPG(r pgdb.Catalog) Catalog {
	return Catalog{ID: r.ID, IntegrationID: r.IntegrationID, Version: r.Version, Tools: r.Tools, CreatedAt: r.CreatedAt}
}

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

func (s *Postgres) LatestCatalog(ctx context.Context, integrationID string) (Catalog, error) {
	r, err := s.q.LatestCatalog(ctx, integrationID)
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromPG(r), nil
}

func (s *Postgres) GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error) {
	r, err := s.q.GetCatalog(ctx, pgdb.GetCatalogParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Catalog{}, fmt.Errorf("store: %w", err)
	}
	return catalogFromPG(r), nil
}

func exposureFromPG(r pgdb.Exposure) Exposure {
	return Exposure{ID: r.ID, IntegrationID: r.IntegrationID, Version: r.Version,
		CatalogVersion: r.CatalogVersion, Entries: r.Entries, CreatedAt: r.CreatedAt}
}

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

func (s *Postgres) LatestExposure(ctx context.Context, integrationID string) (Exposure, error) {
	r, err := s.q.LatestExposure(ctx, integrationID)
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromPG(r), nil
}

func (s *Postgres) GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error) {
	r, err := s.q.GetExposure(ctx, pgdb.GetExposureParams{IntegrationID: integrationID, Version: version})
	if err != nil {
		return Exposure{}, fmt.Errorf("store: %w", err)
	}
	return exposureFromPG(r), nil
}

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

func pendingFromPG(r pgdb.PendingRequest) PendingRequest {
	p := PendingRequest{
		ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Capability: r.Capability,
		Args: r.Args, TrustFlag: r.TrustFlag, Status: r.Status, Result: r.Result,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
	if r.AnsweredAt.Valid {
		p.AnsweredAt = r.AnsweredAt.Int64
	}
	return p
}

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

func (s *Postgres) GetPendingRequest(ctx context.Context, id string) (PendingRequest, error) {
	r, err := s.q.GetPendingRequest(ctx, id)
	if err != nil {
		return PendingRequest{}, fmt.Errorf("store: %w", err)
	}
	return pendingFromPG(r), nil
}

func (s *Postgres) ListOpenPendingRequests(ctx context.Context, accountID string, nowUnix int64) ([]PendingRequest, error) {
	rows, err := s.q.ListOpenPendingRequests(ctx, pgdb.ListOpenPendingRequestsParams{
		AccountID: accountID, ExpiresAt: nowUnix,
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]PendingRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, pendingFromPG(r))
	}
	return out, nil
}

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
