// Package store is the persistence boundary (SPEC §11): one Store contract, one
// implementation per engine — SQLite (default) here, Postgres arriving with P0-05 —
// exercised by a single conformance suite so the engines cannot drift apart.
package store

import (
	"context"
	"errors"
	"time"
)

type Owner struct {
	ID          string
	DisplayName string
	CreatedAt   int64
}

type Account struct {
	ID          string
	Slug        string
	DisplayName string
	Algo        string
	Fingerprint string
	Seal        string
	Status      string
	CreatedAt   int64
	// RootFingerprint is the identity's name and RootCert the root's DER, both empty
	// until the wallet's first leaf is installed; Fingerprint above names the CURRENT
	// leaf key. AcceptNewHosts is the owner's §5.3 setting (auto|ask).
	RootFingerprint string
	RootCert        []byte
	AcceptNewHosts  string
}

// HasRoot reports whether the wallet has issued this identity a leaf yet. An account is made
// with a host key and no root; the first leaf installed names the root, and only then can it be
// served (PACT §2). This used to be asked as `Protocol == 2`, a generation number that had come
// to stand for it.
func (a Account) HasRoot() bool { return a.RootFingerprint != "" }

// Leaf is one certificate this host holds for an account (PACT §2, §14):
// pending (a CSR awaiting the wallet), current, superseded (key kept until
// NotAfter), or former (key destroyed, kid kept for certificate_renewed).
type Leaf struct {
	AccountID string
	Kid       string
	Leaf      []byte
	KeySealed []byte
	NotBefore int64
	NotAfter  int64
	State     string
	Endpoint  string
	CreatedAt int64
	// RequestStateHash is the SHA-256 of the state a web wallet's answer to this pending request
	// must carry, nil once consumed or for a leaf that is not pending (migration 0041).
	// WalletOrigin is the wallet the request went to; "" for one handed over by the CLI.
	RequestStateHash []byte
	WalletOrigin     string
	// Moved is whether installing this leaf moved the identity, as the install decided it
	// (migration 0043): a move's campaign tells every active contact, any other leaf's campaign
	// only the contacts an import left owed the handshake.
	Moved bool
}

// VacatedAddress is an address an identity has left (migration 0040, PACT §9): the endpoint its
// leaves named, the slug that endpoint carries on this node, and the latest notAfter among those
// leaves. It names no identity. Until UntilAt the slug cannot be given to a new account and the
// endpoint cannot be asked for in a signing request.
type VacatedAddress struct {
	Endpoint string
	Slug     string
	UntilAt  int64
	At       int64
}

// ErrAddressVacated is CreateAccount's refusal of a slug an identity has left while the last
// leaf issued for it is live (PACT §9: "An address an identity has vacated MUST NOT be assigned
// to another identity until the last leaf issued for it has expired").
var ErrAddressVacated = errors.New("store: that address was vacated by an identity that left this node, and stays reserved until the last leaf issued for it expires")

// Tombstone remembers a removed root and the leaf that removed it (PACT §5.3).
type Tombstone struct {
	AccountID string
	Root      string
	Leaf      []byte
	At        int64
}

// FormerEndpoint remembers where a pinned root used to answer (PACT §5, §6.1).
type FormerEndpoint struct {
	AccountID string
	Root      string
	Endpoint  string
	At        int64
}

// PendingAddress is a contact at a new address awaiting the owner (PACT §5.3).
type PendingAddress struct {
	AccountID string
	Root      string
	Endpoint  string
	Leaf      []byte
	Why       string
	At        int64
	// RootCert is the root's DER, as for Contact: the owner may sit on this
	// decision for days, and the chain that carried it does not come back.
	RootCert []byte
}

// MoveFanout is per-contact progress of a move campaign's `update_contact` walk (PACT §5.3,
// §9). LeafKid is the leaf being announced: a re-run resumes by matching on it, so a second
// move is a second campaign and not the tail of the first.
type MoveFanout struct {
	AccountID  string
	ContactFpr string
	LeafKid    string
	Status     string // pending | done
	Attempts   int64
	LastError  string
	UpdatedAt  int64
}

// Setting is one owner-set configuration value (SPEC §8.2).
type Setting struct {
	Key       string
	Value     string
	Secret    bool
	UpdatedAt int64
}

type Membership struct {
	OwnerID   string
	AccountID string
	Role      string
}

type Credential struct {
	ID        string
	OwnerID   string
	Kind      string
	Tag       string
	Data      []byte
	CreatedAt int64
}

type Contact struct {
	ID          string
	AccountID   string
	Fingerprint string
	SPKI        []byte
	Status      string // active | pending_in | pending_out | blocked
	Preset      string
	Permissions []string
	TrustFlag   string
	// TheirPermissions is what this contact granted US (PACT §6.2), as opposed
	// to Permissions, which is what we granted them.
	TheirPermissions []string
	DisplayName      string
	// Petname is the OWNER's own name for this contact: optional, local, and
	// beyond any peer's reach. DisplayName is the peer's own claim, so several
	// contacts may share it honestly; this is the name that cannot collide by
	// somebody else's choice. Empty means the owner has expressed no opinion.
	Petname string
	// InviteID names the invite this contact redeemed; empty for a cold
	// request_contact or an owner-initiated add. The label stays live on the
	// invite row — invites are revoked, never deleted.
	InviteID  string
	Card      string
	CreatedAt int64
	PinnedAt  int64
	// PACT 2.0 pins (migration 0027): Protocol 2 means Fingerprint is the ROOT
	// fingerprint, SPKI the pinned leaf's key, Endpoint and Leaf the pin of
	// §14.3. ChainSentKid is our own leaf kid last carried to this contact.
	Endpoint     string
	Leaf         []byte
	ChainSentKid string
	// RootCert is the DER of the root that named this contact (migration 0029).
	// The chain travels once (PACT sec. 13.2), so without it the certificate is
	// gone the moment the envelope that carried it is - the pin keeps the root's
	// fingerprint, and a fingerprint cannot prove a stored leaf, nor can an
	// archive taken here prove its contacts anywhere else. Empty for a pin made
	// before this column existed; filled the next time a chain arrives.
	RootCert []byte
	// EverActive is whether this relationship was ever active (migration 0039). The store sets
	// it whenever a row becomes active and never clears it, and an import writes what the archive
	// carried; it is how an unblock tells a contact the owner blocked (restored) from a request
	// that was rejected (forgotten), SPEC §9.1.
	EverActive bool
	// HandshakeDue says this contact arrived in an import and has not yet heard from this host
	// (migration 0042, PACT §9.2): the campaign of the identity's next leaf owes it
	// update_contact, or request_contact if it refuses that, and clears this when it is told.
	// HandshakeDueAt is when it became owed — the import's time (migration 0043) — so the
	// campaign of a leaf requested before the import does not spend it; an import sets it, and
	// ImportContact refuses a row without it.
	HandshakeDue   bool
	HandshakeDueAt int64
	// RequestedAt is when this row became a request, ours or theirs (migration 0043): the clock
	// the expiry sweep reads (SPEC §9.1). Zero for a row that has never been one.
	RequestedAt int64
}

// ExpiredContact is one unanswered request the expiry sweep removed.
type ExpiredContact struct {
	Fingerprint string
	Status      string // pending_in | pending_out
}

type Invite struct {
	ID          string
	AccountID   string
	TokenHash   []byte
	ExpiresAt   int64
	MaxUses     int64
	Uses        int64
	AutoAccept  bool
	Preset      string
	Permissions []string
	Label       string
	RevokedAt   int64
	CreatedAt   int64
}

type Thread struct {
	ID         string
	AccountID  string
	ContactFpr string
	Topic      string
	CreatedAt  int64
	LastAt     int64
}

type Blob struct {
	AccountID string
	Hash      string
	Size      int64
	Mime      string
	Filename  string
	CreatedAt int64
}

type Message struct {
	Seq        int64
	ID         string
	AccountID  string
	ContactFpr string
	MsgID      string
	ThreadID   string
	Direction  string
	Sender     string
	Kind       string // text | media
	Body       string
	ReplyTo    string
	Status     string
	CreatedAt  int64
	// ExpiresAt is when outbound retries stop (SPEC §7.1). 0 = unset, which the
	// sweeper reads as created_at + 24h, PACT §7's default.
	ExpiresAt int64
	// Attempts and NextAttemptAt are the outbound retry schedule (SPEC §7.1).
	// Backoff is a function of attempts MADE, so it has to survive the sweep
	// that made them — a schedule recomputed from the message's age depends on
	// a sweep landing in a narrow window, and sweeps are not evenly spaced.
	Attempts      int64
	NextAttemptAt int64
}

// Integration is one upstream MCP server row (SPEC §6.1). Status is node-local
// and never wire-visible; credentials live keyring-sealed, never in this row.
type Integration struct {
	ID        string
	AccountID string
	Slug      string
	Transport string // streamable-http | sse | stdio-supervised
	Endpoint  string
	Command   string
	AuthKind  string // none | static | oauth
	Status    string // disabled | connecting | ok | auth_error | unreachable
	CreatedAt int64
	UpdatedAt int64
}

// Catalog is one immutable tool-set snapshot vN (SPEC §6.4); Tools is the JSON
// the integrations package defines.
type Catalog struct {
	ID            string
	IntegrationID string
	Version       int64
	Tools         string
	CreatedAt     int64
}

// Exposure is one immutable exposure set vM bound to catalog vN (SPEC §6.5).
type Exposure struct {
	ID             string
	IntegrationID  string
	Version        int64
	CatalogVersion int64
	Entries        string
	CreatedAt      int64
}

// PendingRequest is one parked agent-answered call (SPEC §6.8).
type PendingRequest struct {
	ID         string
	AccountID  string
	ContactFpr string
	Capability string
	Args       string // peer-supplied, untrusted, stored raw
	TrustFlag  string
	Status     string // open | answered
	Result     string
	CreatedAt  int64
	ExpiresAt  int64
	AnsweredAt int64
}

type Token struct {
	ID        string
	OwnerID   string
	Label     string
	AccountID string // "" = owner-wide
	CreatedAt int64
	RevokedAt int64
}

// AuditAnchorRow is the chain's re-anchor point after archiving (SPEC §11.6).
type AuditAnchorRow struct {
	ArchivedThroughSeq int64
	TerminalHash       string
	ArchivePath        string
	UpdatedAt          int64
}

// AuditPage bounds one read of the trail. Both filters are optional and empty
// means "any"; Account keeps the node's own rows, which belong to no account.
// UndatedIdempotencyWindow is how long an idempotency record written without an expiry is kept
// (SPEC §11: "retained at least until the envelope's `exp`, else 30 days").
const UndatedIdempotencyWindow = 30 * 24 * time.Hour

type AuditPage struct {
	Actor   string
	Account string
	Limit   int
}

type AuditRow struct {
	Seq       int64
	TS        int64
	AccountID string
	ActorKind string
	ActorID   string
	Action    string
	Resource  string
	Outcome   string
	RequestID string
	Details   string
	PrevHash  string
	Hash      string
}

type CreateAccountParams struct {
	Slug        string
	DisplayName string
	Algo        string
}

// Store is the whole persistence surface every engine implements: the role interfaces below,
// one per area of the schema. A consumer that needs one area takes that role, not the whole Store.
type Store interface {
	Lifecycle
	OwnerStore
	AccountStore
	InviteStore
	SettingStore
	ContactStore
	MessageStore
	IntegrationStore
	AuditStore
}

// Lifecycle opens, migrates, closes and transacts: what every engine does before it holds anything.
type Lifecycle interface {
	Migrate(ctx context.Context) error
	// SchemaCurrent reports whether the store's schema is exactly the one this binary migrates
	// to: an error names the two versions when it is behind (a migration has not run) or ahead (a
	// newer binary migrated it). A `serve` that shares the data dir and did not migrate checks it
	// before serving (SPEC §11.1).
	SchemaCurrent(ctx context.Context) error
	Close() error

	// Atomically runs fn against a Store whose every write is ONE transaction: all of it lands,
	// or — if fn returns an error — none of it does. It exists for the importer, where half an
	// identity is worse than none: a person's contacts without their conversations, under a
	// name the node would then refuse to import again. fn must use the Store it is given.
	Atomically(ctx context.Context, fn func(tx Store) error) error

	// Scrub makes what this store has deleted unreadable from its own files, where the engine can:
	// a leaf's key is destroyed, not only deleted (PACT §9, SPEC §3.9). SQLite can, and does; on
	// Postgres it is a no-op, the divergence SPEC §3.9 names. It runs outside any transaction, after
	// a leave, a retirement, an install and a replaced request.
	Scrub(ctx context.Context) error
}

// OwnerStore holds the owners and what authenticates them: credentials, sessions, owner-MCP tokens,
// and which accounts each owner administers (SPEC §3, §8).
type OwnerStore interface {
	// CreateOwnerWithID creates an owner under an id the CALLER chose. Passkey
	// registration needs this: WebAuthn binds a credential to a user handle at
	// the moment the authenticator creates it, and that handle is replayed on
	// every later login. An owner whose id was minted afterwards can never match
	// it (§3.1).
	CreateOwnerWithID(ctx context.Context, id, displayName string) (Owner, error)
	InsertCredential(ctx context.Context, c Credential) error
	CountCredentialsByKind(ctx context.Context, kind string) (int64, error)
	ListCredentialsByKind(ctx context.Context, kind string) ([]Credential, error)

	// There is deliberately NO unguarded RemoveCredential. It existed, with zero
	// callers, as the twin of the method below without the last-one check — a
	// one-call-away re-creation of the owner lockout that guard exists to stop.
	// A credential is removed through RemoveCredentialIfNotLast or not at all.
	//
	// RemoveCredentialIfNotLast deletes a credential only while another of the
	// same kind survives, in one statement. It reports whether it removed one;
	// false with a nil error means "that was the last".
	RemoveCredentialIfNotLast(ctx context.Context, id, kind string) (bool, error)
	InsertSession(ctx context.Context, id, ownerID string, createdAt, expiresAt int64) error
	GetSession(ctx context.Context, id string) (ownerID string, expiresAt int64, err error)
	RemoveSession(ctx context.Context, id string) error

	// DeleteExpiredSessions removes owner sessions past their time. Signing out deletes one and so
	// does presenting an expired one; an abandoned session is never presented again.
	DeleteExpiredSessions(ctx context.Context, now int64) (int64, error)
	InsertToken(ctx context.Context, id, ownerID, label string, hash []byte, accountID string, createdAt int64) error
	GetTokenByHash(ctx context.Context, hash []byte) (Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	RevokeToken(ctx context.Context, id string, now int64) error
	GetOwner(ctx context.Context, id string) (Owner, error)
	ListOwners(ctx context.Context) ([]Owner, error)
	DeleteOwner(ctx context.Context, id string) error
	AddMembership(ctx context.Context, ownerID, accountID, role string) error
	ListMembershipsByOwner(ctx context.Context, ownerID string) ([]Membership, error)
	RemoveMembership(ctx context.Context, ownerID, accountID string) error
}

// AccountStore holds the identities this node answers for: the account rows, their keys, the PACT
// 2.0 root and leaf ledger, and a move's campaign (SPEC §3, PACT §5.3, §9).
type AccountStore interface {
	CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error)

	// SetAccountKey binds the account's first key once: it refuses to overwrite an
	// existing fingerprint. A leaf install moves it, through SetAccountLeafKey.
	SetAccountKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte) error
	GetAccountBySlug(ctx context.Context, slug string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)
	GetAccountByID(ctx context.Context, id string) (Account, error)
	GetAccountSealedKey(ctx context.Context, id string) ([]byte, error)

	// UpdateAccountSeal sets the account's X-PACT-SEAL policy (SPEC §4.6).
	UpdateAccountSeal(ctx context.Context, accountID, seal string) error
	UpsertMoveFanout(ctx context.Context, f MoveFanout) error
	ListMoveFanout(ctx context.Context, accountID string) ([]MoveFanout, error)

	// PACT 2.0 (migration 0027): the account's root and leaf ledger. The same migration's 2.0
	// pins, removal tombstones, former endpoints and pending addresses are ContactStore's.
	SetAccountRoot(ctx context.Context, accountID, rootFingerprint string, rootCert []byte) error
	SetAccountLeafKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte, algo string) error
	SetAccountHostPolicy(ctx context.Context, accountID, acceptNewHosts string) error
	InsertLeaf(ctx context.Context, l Leaf) error
	UpdateLeaf(ctx context.Context, l Leaf) error
	SetLeafMoved(ctx context.Context, accountID, kid string, moved bool) error
	ListLeaves(ctx context.Context, accountID string) ([]Leaf, error)

	// ListKidsExcept is every leaf kid on this node that belongs to some OTHER
	// account. One inbound envelope needs it to tell a kid held for a sibling
	// identity from one this endpoint never held (PACT §13.3, §14.4), and it is
	// one query rather than one per sibling: the per-account form made the cost
	// of every message grow with the number of identities the node hosts.
	ListKidsExcept(ctx context.Context, accountID string) ([]string, error)
	RetireLeafKey(ctx context.Context, accountID, kid string) error

	// ClearAccountKey destroys the account's copy of its current leaf's key and keeps the
	// fingerprint. With RetireLeafKey it is what an expired leaf's key becomes: nothing.
	ClearAccountKey(ctx context.Context, accountID string) error
	DeleteLeavesByState(ctx context.Context, accountID, state string) (int64, error)
	// LockAccount, inside Atomically, makes every other transaction that locks the same account
	// wait until this one ends: a signing request replacing the pending one is one step, never
	// two interleaved (migration 0044). SQLite's transactions are already one at a time.
	LockAccount(ctx context.Context, accountID string) error
	// SetLeafRequest and ConsumeLeafRequest hold a pending request's answer to one use (PACT §9.1,
	// migration 0041): the state's hash goes on with the request and comes off, in one statement
	// that also checks it, when an answer carrying it is installed.
	SetLeafRequest(ctx context.Context, accountID, kid string, stateHash []byte, walletOrigin string) error
	ConsumeLeafRequest(ctx context.Context, accountID, kid string, stateHash []byte) (bool, error)

	// An identity leaving this host (PACT §9, identity.Manager.Leave). DeleteAccount deletes the
	// account row and, by ON DELETE CASCADE, every row that names it by a foreign key;
	// DeleteTokensByAccount and DeleteIdempotencyByAccount are the tables that name it without one.
	DeleteAccount(ctx context.Context, accountID string) (int64, error)
	DeleteTokensByAccount(ctx context.Context, accountID string) (int64, error)
	DeleteIdempotencyByAccount(ctx context.Context, accountID string) (int64, error)
	// UpsertVacatedAddress records an address left behind; a second record of the same endpoint
	// keeps the later UntilAt. LiveVacatedSlug and LiveVacatedEndpoint say whether a record is
	// still reserving it at `now`; DeleteExpiredVacatedAddresses drops the ones that no longer do.
	UpsertVacatedAddress(ctx context.Context, v VacatedAddress) error
	LiveVacatedSlug(ctx context.Context, slug string, now int64) (bool, error)
	LiveVacatedEndpoint(ctx context.Context, endpoint string, now int64) (bool, error)
	ListVacatedAddresses(ctx context.Context) ([]VacatedAddress, error)
	DeleteExpiredVacatedAddresses(ctx context.Context, now int64) (int64, error)
}

// InviteStore holds an account's invites (SPEC §9.2).
type InviteStore interface {
	InsertInvite(ctx context.Context, inv Invite) (Invite, error)
	GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error)

	// GetInviteByHashGlobal resolves a landing-page token with no account in the
	// URL (SPEC §9.2 — /i/<token> carries only the bearer token).
	GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error)
	ListInvites(ctx context.Context, accountID string) ([]Invite, error)

	// ConsumeInviteUse atomically increments uses; false when expired/revoked/exhausted.
	ConsumeInviteUse(ctx context.Context, inviteID string, now int64) (bool, error)

	// RevokeInvite revokes one of THIS account's invites; an id of another account's, or one
	// already revoked, is ErrNotFound. Any other error is the store's own failure.
	RevokeInvite(ctx context.Context, accountID, inviteID string, now int64) error
}

// SettingStore holds the owner-set configuration rows (SPEC §8.2).
type SettingStore interface {
	// ListSettings returns every owner-set configuration row (SPEC §8.2). A row
	// marked Secret holds a keyring-sealed value: callers that render or log
	// settings MUST treat it as opaque.
	ListSettings(ctx context.Context) ([]Setting, error)

	// PutSetting inserts or replaces one owner-set value.
	PutSetting(ctx context.Context, s Setting) error

	// DeleteSetting removes one owner-set value. Unpairing from an ingress has
	// to actually forget the pairing, not blank it.
	DeleteSetting(ctx context.Context, key string) error
}

// ContactStore holds an account's contacts: the relationship, the pin, the grant both ways, and
// what a move leaves behind (tombstones, former endpoints, addresses waiting for the owner) (SPEC
// §9, PACT §5.3, §14.3).
type ContactStore interface {
	// SetContactPetname sets the owner's local name for a contact; "" clears it.
	SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error

	// UpdateContactCard rewrites a contact's card and display name once a card has
	// verified: a refresh the owner asked for (node.RefreshContact) or the peer's own
	// `update_contact`. The pinned root never changes here.
	UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error
	UpsertTombstone(ctx context.Context, t Tombstone) error
	ListTombstones(ctx context.Context, accountID string) ([]Tombstone, error)
	DeleteTombstone(ctx context.Context, accountID, root string) error
	InsertFormerEndpoint(ctx context.Context, f FormerEndpoint) error
	ListFormerEndpoints(ctx context.Context, accountID string) ([]FormerEndpoint, error)
	UpsertPendingAddress(ctx context.Context, p PendingAddress) error
	ListPendingAddresses(ctx context.Context, accountID string) ([]PendingAddress, error)
	GetPendingAddress(ctx context.Context, accountID, root string) (PendingAddress, error)
	DeletePendingAddress(ctx context.Context, accountID, root string) error
	RepinContactAddress(ctx context.Context, accountID, root, endpoint string, leaf, spki []byte, now int64) error

	// SetContactRootCert fills a pin's root certificate when it has none, and
	// leaves an existing one alone: the root of a pin cannot change (PACT sec. 14.3).
	SetContactRootCert(ctx context.Context, accountID, root string, cert []byte) error
	SetContactChainSentKid(ctx context.Context, accountID, fingerprint, kid string) error
	ClearChainSentKids(ctx context.Context, accountID string) error
	InsertContact(ctx context.Context, c Contact) (Contact, error)

	// ImportContact writes a contact that arrived in an export (SPEC §3.10): every column an
	// export carries, and none it does not — no invite, and no record of which of this host's
	// leaves the contact has seen, because this host has not been issued one yet.
	ImportContact(ctx context.Context, c Contact) error
	// ClearContactHandshake records that an imported contact has been sent this host's handshake.
	ClearContactHandshake(ctx context.Context, accountID, fingerprint string) error
	// ImportContactPin gives a contact held with NO leaf the pin an import carries (endpoint, leaf,
	// its key, the root's certificate) and marks it owed the handshake. A contact held with a leaf
	// is left as it is, and false says so: a pin this host validated is never replaced by a file's.
	ImportContactPin(ctx context.Context, c Contact) (bool, error)
	GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error)
	ListContacts(ctx context.Context, accountID string) ([]Contact, error)

	// UpdateContactStatus moves a relationship; a move to active also sets EverActive.
	UpdateContactStatus(ctx context.Context, accountID, fingerprint, status string) error

	// RedeemOverPendingContact is a pending_in row redeeming one of the account's invites: it
	// takes c's status, grant, invite and pin. False when the row is no longer pending_in.
	RedeemOverPendingContact(ctx context.Context, c Contact) (bool, error)

	// MoveContactStatus moves a relationship only if it is still `from`: an owner's decision is
	// written against the status it was taken on. False when the row changed or is gone; a move
	// to active also sets EverActive.
	MoveContactStatus(ctx context.Context, accountID, fingerprint, from, to string) (bool, error)

	// MarkContactRequested makes a contact of status `from` an approach of ours (pending_out)
	// requested at `at`, and leaves EverActive as it was: the handshake's fallback to
	// request_contact, written before the request is sent (PACT §9.2). False when the row changed.
	MarkContactRequested(ctx context.Context, accountID, fingerprint, from string, at int64) (bool, error)
	// TakeBackContactRequest returns a row MarkContactRequested marked at `markedAt` to status
	// `to` and request clock `requestedAt` (0 for none): a request that did not arrive, or was
	// refused. False when the row is no longer that approach.
	TakeBackContactRequest(ctx context.Context, accountID, fingerprint, to string, requestedAt, markedAt int64) (bool, error)

	// DeleteContactInStatus removes the row only while it is still `status`. False when it is not.
	DeleteContactInStatus(ctx context.Context, accountID, fingerprint, status string) (bool, error)

	// DeleteExpiredPendingContacts removes the account's pending_in and pending_out rows whose
	// request was made before cutoff (SPEC §9.1: an unanswered request expires; the clock is
	// Contact.RequestedAt) and reports which went.
	DeleteExpiredPendingContacts(ctx context.Context, accountID string, cutoff int64) ([]ExpiredContact, error)

	// SetContactAccepted records a peer's post-approval card and the permissions
	// THEY granted US (PACT §6.2), and activates the relationship.
	SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error

	// DeleteContact removes the row entirely (SPEC §9.1 `--> none`): the pin
	// and the relationship go, so re-adding starts fresh.
	DeleteContact(ctx context.Context, accountID, fingerprint string) error
	UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error
	UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error
}

// MessageStore holds conversations: threads, messages, media blobs, the idempotency records that
// make a call safe to repeat, and the local deletes retention makes (SPEC §7, §11.2).
type MessageStore interface {
	InsertThread(ctx context.Context, t Thread) error
	// ImportThread, ImportMessage and ImportBlob write what an export carried (SPEC §3.10). Each
	// leaves a row that is already here as it is, so an import into an identity this host already
	// holds adds what it lacks and changes nothing it has; each reports whether it wrote.
	ImportThread(ctx context.Context, t Thread) (bool, error)
	ImportMessage(ctx context.Context, m Message) (bool, error)
	ImportBlob(ctx context.Context, b Blob) (bool, error)
	GetThread(ctx context.Context, accountID, threadID string) (Thread, error)
	TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) error
	InsertMessage(ctx context.Context, m Message) error

	// GetMessageByMsgID looks a message up by the CALLER's idempotency key.
	// direction is part of the key: msg_id is chosen by whoever sent the
	// message, so the two sides of a conversation are separate namespaces.
	GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error)

	// SetMessageStatus records what became of a message after it was written.
	// It only ever touches OUTBOUND rows: a delivery outcome belongs to a
	// message we sent, and the query is scoped to direction='out' so a msg_id
	// shared with an inbound message cannot rewrite the peer's row.
	//
	// an outbound row is `pending` until the peer actually accepts it (§7.1).
	SetMessageStatus(ctx context.Context, accountID, contactFpr, msgID, status string) error

	// SetMessageAttempt records that a delivery attempt was made and when the
	// next one is due. Outbound rows only, like SetMessageStatus.
	SetMessageAttempt(ctx context.Context, accountID, contactFpr, msgID string, attempts, nextAt int64) error

	// ListPendingOutbound returns outbound messages still awaiting delivery,
	// oldest first, across every account (SPEC §7.1).
	ListPendingOutbound(ctx context.Context, limit int32) ([]Message, error)
	ListMessagesByThread(ctx context.Context, accountID, threadID string) ([]Message, error)
	InsertBlob(ctx context.Context, b Blob) error
	GetBlob(ctx context.Context, accountID, hash string) (Blob, error)
	SumBlobBytes(ctx context.Context, accountID string) (int64, error)

	// Retention (SPEC §7.9). All of these delete LOCAL copies only: there is no
	// wire protocol for remote deletion, and the peer's copy is the peer's.
	DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error)
	DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error)

	// ListMediaBodies returns the bodies of an account's media messages, oldest first: what
	// retention reads to learn which media a retained message still references.
	ListMediaBodies(ctx context.Context, accountID string) ([]string, error)
	ListBlobs(ctx context.Context, accountID string) ([]Blob, error)
	DeleteBlob(ctx context.Context, accountID, hash string) (int64, error)

	// CountBlobRefs counts rows for a hash ACROSS accounts: the blob store is
	// content-addressed, so the file may only be removed once nobody refers to it.
	CountBlobRefs(ctx context.Context, hash string) (int64, error)
	ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error)
	UnreadCount(ctx context.Context, accountID, threadID string) (int64, error)
	MarkThreadRead(ctx context.Context, accountID, threadID string) error

	// Two callers share this table and MUST NOT share a key. An envelope's
	// replay guard reserves public.EnvelopeKey(msg_id); a tool that carries its
	// own msg_id (book_slot) reserves the bare one. They collided once —
	// call_contact sends the tool's msg_id as the envelope's, so a sealed
	// booking reserved the id as an envelope and then read its own reservation
	// as another attempt in flight. Any new caller needs a namespace of its own.
	//
	// PutIdempotency records msg_id's acknowledgment once (SPEC §11.2): the
	// first writer wins; every caller gets back the stored ack and whether it
	// pre-existed. expiresAt 0 = no expiry.
	PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (stored string, existed bool, err error)

	// UpdateIdempotencyAck upgrades an in-flight reservation to the final ack.
	UpdateIdempotencyAck(ctx context.Context, accountID, contactFpr, msgID, ack string) error

	// DeleteExpiredIdempotency removes the records whose window has closed: a dated one at its
	// expiry, an undated one after UndatedIdempotencyWindow. A sealed call writes one of these
	// every time, so a node that never removes them holds one for every call it ever took.
	DeleteExpiredIdempotency(ctx context.Context, now int64) (int64, error)
}

// IntegrationStore holds an account's integrations: the rows, their catalog and exposure versions,
// sealed credentials, and agent-answered requests waiting (SPEC §6).
type IntegrationStore interface {
	// Integrations (SPEC §6.1): CRUD + node-local status.
	InsertIntegration(ctx context.Context, in Integration) (Integration, error)
	GetIntegration(ctx context.Context, accountID, slug string) (Integration, error)
	GetIntegrationByID(ctx context.Context, id string) (Integration, error)
	ListIntegrations(ctx context.Context, accountID string) ([]Integration, error)
	UpdateIntegrationStatus(ctx context.Context, id, status string) error
	UpdateIntegrationConfig(ctx context.Context, id, transport, endpoint, command, authKind string) error
	DeleteIntegration(ctx context.Context, id string) error

	// InsertCatalog stores an immutable snapshot; Version must be Latest+1.
	InsertCatalog(ctx context.Context, c Catalog) (Catalog, error)
	LatestCatalog(ctx context.Context, integrationID string) (Catalog, error)
	GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error)

	// InsertExposure stores an immutable exposure set; Version must be Latest+1.
	InsertExposure(ctx context.Context, e Exposure) (Exposure, error)
	LatestExposure(ctx context.Context, integrationID string) (Exposure, error)
	GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error)

	// Pending agent-answered requests (SPEC §6.8).
	InsertPendingRequest(ctx context.Context, p PendingRequest) (PendingRequest, error)
	GetPendingRequest(ctx context.Context, id string) (PendingRequest, error)
	ListOpenPendingRequests(ctx context.Context, accountID string, now int64) ([]PendingRequest, error)

	// AnswerPendingRequest closes an OPEN, unexpired row; reports whether it did.
	AnswerPendingRequest(ctx context.Context, id, result string, answeredAt, now int64) (bool, error)

	// SetIntegrationSecret stores the keyring-sealed credential blob (SPEC §6.3).
	SetIntegrationSecret(ctx context.Context, id string, sealed []byte) error
	GetIntegrationSecret(ctx context.Context, id string) ([]byte, error)
}

// AuditStore holds the hash-chained audit trail and its archive anchor (SPEC §11).
type AuditStore interface {
	// AppendAuditEvent extends the chain by one row (SPEC §11.4). In ONE transaction it reads the
	// head — the last row's seq and hash, or 0 and "" for an empty chain — hands it to seal, and
	// inserts the row seal builds on it. The transaction holds the chain's head for its length, so
	// every process appending to one store takes turns: on SQLite the transaction takes the write
	// lock at BEGIN, on Postgres it takes an advisory lock (LockAuditChain) before it reads. No
	// process carries the head in memory between appends.
	AppendAuditEvent(ctx context.Context, seal func(prevSeq int64, prevHash string) (AuditRow, error)) error
	InsertAuditEvent(ctx context.Context, seq int64, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) error
	LastAuditEvent(ctx context.Context) (seq int64, hash string, err error)
	ListAuditEvents(ctx context.Context, actorFilter string) ([]AuditRow, error)

	// ListAuditEventsPage is the trail as it is READ: newest first and bounded.
	// ListAuditEvents above is the trail as it is VERIFIED — ascending, whole —
	// and a reader that wanted neither of those was loading every row ever
	// written to filter eight of them in a browser.
	ListAuditEventsPage(ctx context.Context, p AuditPage) ([]AuditRow, error)

	// AuditAnchor reports what the retained chain is expected to extend: the
	// terminal hash of the archived segment (SPEC §11.6). Never archived = a
	// zero AuditAnchorRow, meaning the chain must still start at genesis.
	AuditAnchor(ctx context.Context) (AuditAnchorRow, error)

	// SetAuditAnchor records an archive's terminal hash.
	SetAuditAnchor(ctx context.Context, a AuditAnchorRow) error

	// DeleteAuditEventsThrough prunes the head of the chain once the anchor above records what
	// was removed (SPEC §11.6). It is one of the two deletes on the chain; ArchiveAuditRows is
	// the other.
	DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error)

	// ListDueLeaves lists the account_leave rows of the identities whose leave went through (ok,
	// or partial) at or before `before` (unix seconds), oldest first, at most `limit` of them:
	// the identities whose trail is due to be archived (SPEC §3.11).
	ListDueLeaves(ctx context.Context, before int64, limit int) ([]AuditRow, error)

	// ArchiveAuditRows removes exactly these rows, each named by its seq AND its hash, from the
	// chain, in one transaction: it lists them in audit_archive_rows (the only thing the prune
	// guard admits for a row the head anchor does not cover), deletes them, and empties the list
	// again. A row whose hash differs from the one named is not deleted, and then nothing is: the
	// count must be every row named, or the transaction is rolled back. It is the second of the
	// two deletes on the chain, and its caller has written the rows to an archive and read them
	// back first (audit.ArchiveDeparted).
	ArchiveAuditRows(ctx context.Context, rows []AuditArchiveRow) (int64, error)
}

// AuditArchiveRow names one audit row an archive holds: its seq and the hash it was written with.
type AuditArchiveRow struct {
	Seq  int64
	Hash string
}
