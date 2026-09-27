package store

import (
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

// A row becomes its domain type HERE, once, for both engines. sqlc generates the two queriers'
// row types separately, and sqlc.yaml's overrides make the Postgres ones the same shape as the
// SQLite ones, so the Postgres adapter converts its row (sqlitedb.Contact(r)) and calls the same
// mapper. The conversion is the check: a column that differs between the two schemas is a compile
// error in the Postgres adapter, not a second mapper that quietly reads it differently.

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
		EverActive:       r.EverActive != 0,
	}
}

func inviteFromRow(r sqlitedb.Invite) Invite {
	return Invite{
		ID: r.ID, AccountID: r.AccountID, TokenHash: r.TokenHash, ExpiresAt: r.ExpiresAt,
		MaxUses: r.MaxUses, Uses: r.Uses, AutoAccept: r.AutoAccept != 0, Preset: r.Preset,
		Permissions: permsFromJSON(r.Permissions), Label: r.Label,
		RevokedAt: r.RevokedAt.Int64, CreatedAt: r.CreatedAt,
	}
}

func messageFromRow(r sqlitedb.Message) Message {
	return Message{
		Seq: r.Seq, ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, MsgID: r.MsgID,
		ThreadID: r.ThreadID, Direction: r.Direction, Sender: r.Sender, Kind: r.Kind, Body: r.Body,
		ReplyTo: r.ReplyTo, Status: r.Status, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, Attempts: r.Attempts, NextAttemptAt: r.NextAttemptAt,
	}
}

func integrationFromRow(r sqlitedb.Integration) Integration {
	return Integration{
		ID: r.ID, AccountID: r.AccountID, Slug: r.Slug, Transport: r.Transport,
		Endpoint: r.Endpoint, Command: r.Command, AuthKind: r.AuthKind,
		Status: r.Status, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func catalogFromRow(r sqlitedb.Catalog) Catalog {
	return Catalog{ID: r.ID, IntegrationID: r.IntegrationID, Version: r.Version, Tools: r.Tools, CreatedAt: r.CreatedAt}
}

func exposureFromRow(r sqlitedb.Exposure) Exposure {
	return Exposure{ID: r.ID, IntegrationID: r.IntegrationID, Version: r.Version,
		CatalogVersion: r.CatalogVersion, Entries: r.Entries, CreatedAt: r.CreatedAt}
}

func pendingFromRow(r sqlitedb.PendingRequest) PendingRequest {
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

func accountFromRow(r sqlitedb.Account) Account {
	return Account{
		ID: r.ID, Slug: r.Slug, DisplayName: r.DisplayName, Algo: r.Algo,
		Fingerprint: r.Fingerprint.String, Seal: r.Seal, Status: r.Status, CreatedAt: r.CreatedAt,
		RootFingerprint: r.RootFingerprint.String, RootCert: r.RootCert,
		AcceptNewHosts: r.AcceptNewHosts,
	}
}

func tokenFromRow(r sqlitedb.Token) Token {
	t := Token{ID: r.ID, OwnerID: r.OwnerID, Label: r.Label, CreatedAt: r.CreatedAt}
	if r.AccountID.Valid {
		t.AccountID = r.AccountID.String
	}
	t.RevokedAt = r.RevokedAt.Int64
	return t
}

func auditFromRow(r sqlitedb.AuditEvent) AuditRow {
	acct := ""
	if r.AccountID.Valid {
		acct = r.AccountID.String
	}
	return AuditRow{
		Seq: r.Seq, TS: r.Ts, AccountID: acct, ActorKind: r.ActorKind, ActorID: r.ActorID,
		Action: r.Action, Resource: r.Resource, Outcome: r.Outcome, RequestID: r.RequestID,
		Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
	}
}

// contactChanged is the answer of a write to one contact, from what the statement returned: its
// error, or "contact not found" when it changed no row. Both engines' contact writes end in it.
func contactChanged(n int64, err error) error {
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}
