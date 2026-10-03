package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// leafFingerprint is the `leaf_fingerprint` column a row holding `leaf` carries:
// the fingerprint of the leaf's key, which the row keeps beside it in `spki`. NULL exactly when
// there is no leaf. Every statement that writes `leaf` writes this with it; PinCandidates finds a
// small form's pin by it, so a writer that left it out would leave that contact unfindable.
func leafFingerprint(leaf, spki []byte) sql.NullString {
	if len(leaf) == 0 {
		return sql.NullString{}
	}
	return keyFingerprint(spki)
}

// keyFingerprint is hdtp-identity's fingerprint of a key, as the column holds it; NULL for no key.
func keyFingerprint(spki []byte) sql.NullString {
	if len(spki) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: hdtpidentity.Fingerprint(spki), Valid: true}
}

// A domain value becomes a statement's parameters HERE, once, for both engines, with the defaults
// a new row takes. The engines' generated parameter types are the same shape (sqlc.yaml's
// overrides), so the Postgres adapter converts what these return (pgdb.InsertContactParams(p)),
// and the compiler refuses the conversion the day the two drift. Only the writes whose parameters
// carry logic — a default, an encoding, a NULL — are here; a statement that takes two plain
// arguments is clearer written where it is called.
//
// Five generated types differ between the engines and stay per engine: the two audit-page
// parameter types (sqlc types LIMIT int32 on Postgres, int64 on SQLite),
// DeleteCredentialIfNotLast's (SQLite passes the kind twice as `?`, Postgres names it once as $2),
// and Setting's and PutSetting's (`secret` is boolean on Postgres and INTEGER on SQLite).

// contactInsert fills a new contact's defaults into c and returns InsertContact's parameters.
func contactInsert(c *Contact) sqlitedb.InsertContactParams {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	return sqlitedb.InsertContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		DisplayName: c.DisplayName, Card: c.Card, CreatedAt: c.CreatedAt, InviteID: c.InviteID,
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, LeafFingerprint: leafFingerprint(c.Leaf, c.SPKI), ChainSentKid: c.ChainSentKid,
		RootCert: c.RootCert, EverActive: everActive(c.Status), RequestedAt: requestedAt(c.Status, c.CreatedAt),
	}
}

// requestedAt is the request clock a row written with this status starts with:
// its creation, when it is written as a request, and none otherwise.
func requestedAt(status string, createdAt int64) sql.NullInt64 {
	if status == "pending_in" || status == "pending_out" {
		return sql.NullInt64{Int64: createdAt, Valid: true}
	}
	return sql.NullInt64{}
}

// nullUnix is a unix time as a nullable column: zero is NULL.
func nullUnix(t int64) sql.NullInt64 { return sql.NullInt64{Int64: t, Valid: t != 0} }

// contactImport returns ImportContact's parameters for an archived contact, giving it an id if it
// has none. An imported contact is owed the handshake from a time the caller names.
func contactImport(c Contact) (sqlitedb.ImportContactParams, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.HandshakeDueAt <= 0 {
		return sqlitedb.ImportContactParams{}, fmt.Errorf("store: imported contact %s names no time its handshake became owed", c.Fingerprint)
	}
	return sqlitedb.ImportContactParams{
		ID: c.ID, AccountID: c.AccountID, Fingerprint: c.Fingerprint, Spki: c.SPKI,
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions),
		TheirPermissions: permsToJSON(c.TheirPermissions), TrustFlag: c.TrustFlag,
		DisplayName: c.DisplayName, Petname: c.Petname, Card: c.Card, CreatedAt: c.CreatedAt,
		PinnedAt: sql.NullInt64{Int64: c.PinnedAt, Valid: c.PinnedAt != 0},
		Endpoint: c.Endpoint, Leaf: c.Leaf, LeafFingerprint: leafFingerprint(c.Leaf, c.SPKI), RootCert: c.RootCert,
		// What the export says (its was_active), and active is always a contact.
		EverActive:   importedEverActive(c),
		HandshakeDue: c.HandshakeDueAt,
		RequestedAt:  requestedAt(c.Status, c.CreatedAt),
	}, nil
}

// pinCandidates returns PinCandidates' parameters.
func pinCandidates(accountID, root, endpoint, leafFingerprint string) sqlitedb.PinCandidatesParams {
	return sqlitedb.PinCandidatesParams{
		AccountID: accountID, Fingerprint: root, Endpoint: endpoint,
		LeafFingerprint: sql.NullString{String: leafFingerprint, Valid: true},
	}
}

// contactPin returns ImportContactPin's parameters. A nil root certificate keeps the one the row
// holds; the handshake is owed from the time the caller names, as for ImportContact.
func contactPin(c Contact) (sqlitedb.ImportContactPinParams, error) {
	if c.HandshakeDueAt <= 0 {
		return sqlitedb.ImportContactPinParams{}, fmt.Errorf("store: imported pin %s names no time its handshake became owed", c.Fingerprint)
	}
	var rootCert []byte
	if len(c.RootCert) > 0 {
		rootCert = c.RootCert
	}
	return sqlitedb.ImportContactPinParams{
		Endpoint: c.Endpoint, Leaf: c.Leaf, LeafFingerprint: leafFingerprint(c.Leaf, c.SPKI), Spki: c.SPKI, RootCert: rootCert, HandshakeDue: c.HandshakeDueAt,
		AccountID: c.AccountID, Fingerprint: c.Fingerprint,
	}, nil
}

// contactRedeem returns RedeemOverPendingContact's parameters.
func contactRedeem(c Contact) sqlitedb.RedeemOverPendingContactParams {
	var rootCert []byte
	if len(c.RootCert) > 0 {
		rootCert = c.RootCert // nil keeps the certificate the row already holds
	}
	return sqlitedb.RedeemOverPendingContactParams{
		Status: c.Status, Preset: c.Preset, Permissions: permsToJSON(c.Permissions), InviteID: c.InviteID,
		DisplayName: c.DisplayName, Card: c.Card, Spki: c.SPKI, Endpoint: c.Endpoint, Leaf: c.Leaf,
		RootCert: rootCert, AccountID: c.AccountID, Fingerprint: c.Fingerprint, LeafFingerprint: leafFingerprint(c.Leaf, c.SPKI),
	}
}

// contactAccepted returns SetContactAccepted's parameters: what the peer granted, as JSON, and
// the moment the pin was made.
func contactAccepted(accountID, fingerprint, card string, theirPermissions []string, now int64) (sqlitedb.SetContactAcceptedParams, error) {
	if theirPermissions == nil {
		theirPermissions = []string{}
	}
	raw, err := json.Marshal(theirPermissions)
	if err != nil {
		return sqlitedb.SetContactAcceptedParams{}, err
	}
	return sqlitedb.SetContactAcceptedParams{
		Card: card, TheirPermissions: string(raw), PinnedAt: sql.NullInt64{Int64: now, Valid: true},
		AccountID: accountID, Fingerprint: fingerprint,
	}, nil
}

// messageInsert returns InsertMessage's parameters, giving the message an id if it has none.
func messageInsert(m Message) sqlitedb.InsertMessageParams {
	if m.ID == "" {
		m.ID = newID()
	}
	return sqlitedb.InsertMessageParams{
		ID: m.ID, AccountID: m.AccountID, ContactFpr: m.ContactFpr, MsgID: m.MsgID,
		ThreadID: m.ThreadID, Direction: m.Direction, Sender: m.Sender, Kind: kindOrText(m.Kind), Body: m.Body,
		ReplyTo: m.ReplyTo, Status: m.Status, CreatedAt: m.CreatedAt, ExpiresAt: m.ExpiresAt,
	}
}

// messageImport returns ImportMessage's parameters: a message an export carried, which keeps its id.
func messageImport(m Message) sqlitedb.ImportMessageParams {
	return sqlitedb.ImportMessageParams{
		ID: m.ID, AccountID: m.AccountID, ContactFpr: m.ContactFpr, MsgID: m.MsgID,
		ThreadID: m.ThreadID, Direction: m.Direction, Sender: m.Sender, Kind: kindOrText(m.Kind), Body: m.Body,
		ReplyTo: m.ReplyTo, Status: m.Status, CreatedAt: m.CreatedAt,
	}
}

// inviteInsert fills a new invite's defaults into inv and returns InsertInvite's parameters.
func inviteInsert(inv *Invite) sqlitedb.InsertInviteParams {
	if inv.ID == "" {
		inv.ID = newID()
	}
	if inv.CreatedAt == 0 {
		inv.CreatedAt = now()
	}
	if inv.MaxUses == 0 {
		inv.MaxUses = 1
	}
	return sqlitedb.InsertInviteParams{
		ID: inv.ID, AccountID: inv.AccountID, TokenHash: inv.TokenHash,
		ExpiresAt: inv.ExpiresAt, MaxUses: inv.MaxUses, AutoAccept: b2i(inv.AutoAccept),
		Preset: inv.Preset, Permissions: permsToJSON(inv.Permissions), Label: inv.Label,
		CreatedAt: inv.CreatedAt,
	}
}

// integrationInsert fills a new integration's defaults into in and returns InsertIntegration's
// parameters.
func integrationInsert(in *Integration) sqlitedb.InsertIntegrationParams {
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
	return sqlitedb.InsertIntegrationParams{
		ID: in.ID, AccountID: in.AccountID, Slug: in.Slug, Transport: in.Transport,
		Endpoint: in.Endpoint, Command: in.Command, AuthKind: in.AuthKind,
		Status: in.Status, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	}
}

// auditInsert returns InsertAuditEvent's parameters; an event about no account stores NULL.
func auditInsert(seq, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) sqlitedb.InsertAuditEventParams {
	return sqlitedb.InsertAuditEventParams{
		Seq: seq, Ts: ts, AccountID: sql.NullString{String: accountID, Valid: accountID != ""}, ActorKind: actorKind, ActorID: actorID,
		Action: action, Resource: resource, Outcome: outcome, RequestID: requestID,
		Details: details, PrevHash: prevHash, Hash: hash,
	}
}

// tokenInsert returns InsertToken's parameters; a token scoped to no account stores NULL.
func tokenInsert(id, ownerID, label string, hash []byte, accountID string, createdAt int64) sqlitedb.InsertTokenParams {
	return sqlitedb.InsertTokenParams{
		ID: id, OwnerID: ownerID, Label: label, Hash: hash,
		AccountID: sql.NullString{String: accountID, Valid: accountID != ""}, CreatedAt: createdAt,
	}
}
