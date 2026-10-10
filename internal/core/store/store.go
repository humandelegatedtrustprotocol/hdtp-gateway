// Package store is the persistence boundary (SPEC §11): one Store contract, one
// implementation per engine — SQLite (default) here, Postgres arriving with P0-05 —
// exercised by a single conformance suite so the engines cannot drift apart.
package store

import (
	"context"
	"time"
)

// Owner is a person who administers accounts on this node, the principal that credentials, sessions
// and owner-MCP tokens authenticate (OwnerStore). ID is the id a WebAuthn user handle names when the
// owner was created by CreateOwnerWithID.
type Owner struct {
	ID          string
	DisplayName string
	CreatedAt   int64
}

// Account is one identity this node answers for (SPEC §3). Fingerprint names the key it signs and
// seals with today and Seal is the sealing policy its card advertises. RootFingerprint, RootCert and
// AcceptNewHosts are set once a wallet has issued the first leaf; the certificates themselves are
// Leaf rows. Status is active or suspended, as the table's CHECK holds it.
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
// served (HDTP §2). This used to be asked of a `Protocol` number that had come
// to stand for it.
func (a Account) HasRoot() bool { return a.RootFingerprint != "" }

// Leaf is one certificate this host holds for an account (HDTP §2, §14):
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
	// must carry, nil once consumed or for a leaf that is not pending.
	// AnsweredStateHash is that hash once an answer carrying it was installed: consuming the
	// request moves it here, so an answer that arrives again is known for one.
	// WalletOrigin is the wallet the request went to; "" for one handed over by the CLI.
	RequestStateHash  []byte
	AnsweredStateHash []byte
	WalletOrigin      string
	// Moved is whether installing this leaf moved the identity, as the install decided it
	//: a move's campaign tells every active contact, any other leaf's campaign
	// only the contacts an import left owed the handshake.
	Moved bool
}

// Tombstone remembers a removed root and the leaf that removed it (HDTP §5.3).
type Tombstone struct {
	AccountID string
	Root      string
	Leaf      []byte
	At        int64
}

// FormerEndpoint remembers where a pinned root used to answer (HDTP §5, §6.1).
type FormerEndpoint struct {
	AccountID string
	Root      string
	Endpoint  string
	At        int64
}

// PendingAddress is a contact at a new address awaiting the owner (HDTP §5.3).
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

// MoveFanout is per-contact progress of a move campaign's `update_contact` walk (HDTP §5.3,
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

// Membership records that an owner administers an account. Role is a value the table's CHECK admits,
// and that is "admin" alone.
type Membership struct {
	OwnerID   string
	AccountID string
	Role      string
}

// Credential is something an owner authenticates with. Kind is passkey, oauth or password, as the
// table's CHECK holds it; Data is opaque to the store and Tag is a label.
type Credential struct {
	ID        string
	OwnerID   string
	Kind      string
	Tag       string
	Data      []byte
	CreatedAt int64
}

// Contact is one relationship an account holds, and the pin that goes with it (HDTP §14.3). Status
// is active, pending_in, pending_out or blocked, as the table's CHECK holds it, and TrustFlag is
// messages_only or may_instruct. Permissions is what the account granted the contact and
// TheirPermissions what the contact granted it; both are stored as JSON arrays, and stored text that
// is not valid JSON reads back as an empty list. In the pin, Fingerprint is the root's, SPKI is the
// pinned leaf's key, and Endpoint, Leaf and RootCert are the address, the leaf and the root
// certificate it was made from.
type Contact struct {
	ID          string
	AccountID   string
	Fingerprint string
	SPKI        []byte
	Status      string // active | pending_in | pending_out | blocked
	Preset      string
	Permissions []string
	TrustFlag   string
	// TheirPermissions is what this contact granted US (HDTP §6.2), as opposed
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
	// The pin (HDTP §14.3): Fingerprint above is the ROOT's, SPKI the pinned
	// leaf's key, and Endpoint and Leaf the address and the leaf pinned. ChainSentKid is our own leaf kid last carried to this contact.
	Endpoint     string
	Leaf         []byte
	ChainSentKid string
	// RootCert is the DER of the root that named this contact.
	// The chain travels once (HDTP sec. 13.2), so without it the certificate is
	// gone the moment the envelope that carried it is - the pin keeps the root's
	// fingerprint, and a fingerprint cannot prove a stored leaf, nor can an
	// archive taken here prove its contacts anywhere else. Empty for a pin made
	// before this column existed; filled the next time a chain arrives.
	RootCert []byte
	// EverActive is whether this relationship was ever active. The store sets
	// it whenever a row becomes active and never clears it, and an import writes what the archive
	// carried; it is how an unblock tells a contact the owner blocked (restored) from a request
	// that was rejected (forgotten), SPEC §9.1.
	EverActive bool
	// HandshakeDue says this contact arrived in an import and has not yet heard from this host
	// (HDTP §9.2): the campaign of the identity's next leaf owes it
	// update_contact, or request_contact if it refuses that, and clears this when it is told.
	// HandshakeDueAt is when it became owed — the import's time — so the
	// campaign of a leaf requested before the import does not spend it; an import sets it, and
	// ImportContact refuses a row without it.
	HandshakeDue   bool
	HandshakeDueAt int64
	// RequestedAt is when this row became a request, ours or theirs: the clock
	// the expiry sweep reads (SPEC §9.1). Zero for a row that has never been one.
	RequestedAt int64
}

// ExpiredContact is one unanswered request the expiry sweep removed.
type ExpiredContact struct {
	Fingerprint string
	Status      string // pending_in | pending_out
}

// Invite is an account's invitation to become a contact (SPEC §9.2). Only the hash of its token is
// stored. An invite is revoked, never deleted: RevokedAt is set and the row stays, so the label on a
// contact that redeemed it stays live. ExpiresAt, MaxUses and Uses bound its redemption
// (ConsumeInviteUse).
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

// Thread is one conversation topic between an account and a contact. LastAt is its last activity
// time; the read marker (last_read_seq) is kept in the table and is reached through the read-state
// methods of MessageStore, not through this type.
type Thread struct {
	ID         string
	AccountID  string
	ContactFpr string
	Topic      string
	CreatedAt  int64
	LastAt     int64
	// KeptDisplayName and KeptPetname are the contact row's display_name and petname as the row
	// was deleted (a trigger writes them: migrations 0002). They name a thread whose contact is
	// gone; while a row names ContactFpr, the row's names are the ones that count.
	KeptDisplayName string
	KeptPetname     string
	// KeptWasContact says the thread's root was ever a contact when its row was deleted (migrations
	// 0004), or, for a thread written before that migration, that the thread holds a message, which
	// only a contact's conversation can: a former contact's conversation, which an export carries
	// (HDTP §9.2).
	KeptWasContact bool
}

// KeptNames is what a root's threads kept of its names: Petname and DisplayName.
type KeptNames struct{ Petname, DisplayName string }

// KeptNamesByRoot is, for each root of `threads` (newest first, as ListThreadsByAccount answers),
// each of the names its threads kept, the first that is not empty, newest first: a thread a root
// opened when its row held no name keeps none, and does not hide the names an older thread kept.
// The export (a removed thread's names) and the conversation list (a former contact's label) both
// read a root's names here.
func KeptNamesByRoot(threads []Thread) map[string]KeptNames {
	out := map[string]KeptNames{}
	for _, t := range threads {
		k := out[t.ContactFpr]
		if k.Petname == "" {
			k.Petname = t.KeptPetname
		}
		if k.DisplayName == "" {
			k.DisplayName = t.KeptDisplayName
		}
		out[t.ContactFpr] = k
	}
	return out
}

// Blob is the record of an inline media file an account holds, named by the hash of its content. The
// file is on disk under the node's blob directory; the row is only its record.
type Blob struct {
	AccountID string
	Hash      string
	Size      int64
	Mime      string
	Filename  string
	CreatedAt int64
}

// Message is one message of a thread. Seq is the order the store wrote it in, ID is the store's id,
// and MsgID is the sender-chosen idempotency key, unique per account, contact and Direction.
// Direction is in or out, Sender is agent or human, Kind is text or media, and Status is delivered,
// queued_for_human, pending or failed, all as the table's CHECKs hold them.
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
	// sweeper reads as created_at + 24h, HDTP §7's default.
	ExpiresAt int64
	// Attempts and NextAttemptAt are the outbound retry schedule (SPEC §7.1).
	// Backoff is a function of attempts MADE, so it has to survive the sweep
	// that made them — a schedule recomputed from the message's age depends on
	// a sweep landing in a narrow window, and sweeps are not evenly spaced.
	Attempts      int64
	NextAttemptAt int64
}

// DefaultMessageExpiry is HDTP §7's outbound deadline: retries stop after 24 hours.
const DefaultMessageExpiry = 24 * time.Hour

// Deadline is when the retry sweep gives an outbound message up (unix seconds): its own expiry, or
// created_at + DefaultMessageExpiry when it has none (0 is unset, SPEC §7.1). The sweep and the
// inbox's "trying again until" line both read it here, so they cannot disagree.
func (m Message) Deadline() int64 {
	if m.ExpiresAt > 0 {
		return m.ExpiresAt
	}
	return m.CreatedAt + int64(DefaultMessageExpiry/time.Second)
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

// Token is an owner-MCP token, found by the hash of its secret and never holding the secret.
// AccountID is empty for a token that acts for the owner on every account. RevokedAt is zero until
// it is revoked.
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

// UndatedIdempotencyWindow is how long an idempotency record written without an expiry is kept:
// a `book_slot` replay's (SPEC §11). An envelope's record carries its own, the end of the window
// it can be accepted in (HDTP §13.3; public.replayWindowEnd).
const UndatedIdempotencyWindow = 30 * 24 * time.Hour

// AuditPage bounds one read of the trail. Both filters are optional and empty
// means "any"; Account keeps the node's own rows, which belong to no account.
type AuditPage struct {
	Actor   string
	Account string
	Limit   int
}

// AuditRow is one row of the audit chain as the store holds it. PrevHash and Hash are lowercase hex;
// the audit package is what computes them (audit.Next), and the store only keeps what it is given.
// AccountID is empty for a row about no account, stored as NULL.
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

// CreateAccountParams are the fields a new account is made from. Algo is p256 or ed25519, as the
// table's CHECK holds it.
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
	ChangeStore
	PresenceStore
	LeaseStore
}

// LeaseStore hands background work to one node process at a time (SPEC §11.1).
type LeaseStore interface {
	// TakeLease takes the named lease for holder until the unix second until, or renews it if
	// holder has it; it reports false, and changes nothing, while another holder's lease has not
	// run out by now.
	TakeLease(ctx context.Context, name, holder string, now, until int64) (bool, error)
	// ReleaseLease lets holder's lease go, if it holds it.
	ReleaseLease(ctx context.Context, name, holder string) error
}

// PresenceStore keeps when the owner's agent last asked the owner MCP anything (SPEC §6.8), so
// that every node process sharing the store answers "is the agent attached" the same.
type PresenceStore interface {
	// TouchOwnerPresence records that the owner's agent asked at the given time, replacing the
	// single presence row. The time is stored as given and may be earlier than the one it replaces.
	TouchOwnerPresence(ctx context.Context, at int64) error
	// OwnerPresenceSeenAt is 0 when the agent has never asked.
	OwnerPresenceSeenAt(ctx context.Context) (int64, error)
}

// Change is one row of the change log (SPEC §7.8): something happened that a waiter in any node
// process sharing this store may want to wake for. ID is the cursor, store-assigned and
// committed in order.
type Change struct {
	ID         int64
	AccountID  string
	Kind       string
	ThreadID   string
	ContactFpr string
	Ref        string
	At         int64
}

// ChangeStore is the change log every node process sharing a store reads and writes.
type ChangeStore interface {
	// AppendChange records c (its ID is ignored) and returns the id assigned. Ids commit in the
	// order they are assigned: on Postgres every insert first takes one advisory lock in its
	// transaction, and sends a notification at its commit; SQLite writes one transaction at a time.
	AppendChange(ctx context.Context, c Change) (int64, error)
	// ChangesAfter returns up to limit changes with ids above after, in id order.
	ChangesAfter(ctx context.Context, after int64, limit int) ([]Change, error)
	// AccountChangesAfter returns up to limit of one account's changes with ids above after.
	AccountChangesAfter(ctx context.Context, accountID string, after int64, limit int) ([]Change, error)
	// ChangeBounds returns the oldest and newest ids held, 0 and 0 for an empty log.
	ChangeBounds(ctx context.Context) (oldest, newest int64, err error)
	// DeleteChangesBefore prunes the log of changes written before at (unix seconds).
	DeleteChangesBefore(ctx context.Context, at int64) (int64, error)
	// WatchChanges calls wake whenever another process may have appended, until ctx ends. It is a
	// hint that shortens the wait for the next poll, never the source of truth: Postgres
	// LISTENs for the notification AppendChange sends; SQLite has none, and returns at once.
	WatchChanges(ctx context.Context, wake func()) error
}

// Lifecycle opens, migrates, closes and transacts: what every engine does before it holds anything.
type Lifecycle interface {
	// Migrate applies every pending migration of the engine's schema (migrations/sqlite or
	// migrations/postgres). Postgres processes sharing a database take turns under a session-level
	// advisory lock.
	Migrate(ctx context.Context) error
	// SchemaCurrent reports whether the store's schema is exactly the one this binary migrates
	// to: an error names the two versions when it is behind (a migration has not run) or ahead (a
	// newer binary migrated it). A `serve` that shares the data dir and did not migrate checks it
	// before serving (SPEC §11.1).
	SchemaCurrent(ctx context.Context) error
	// Close releases the engine's connections. SQLite's closes its pool and returns the driver's error;
	// Postgres's closes the pool and returns nil.
	Close() error

	// Atomically runs fn against a Store whose every write is ONE transaction: all of it lands,
	// or — if fn returns an error — none of it does. It exists for the importer, where half an
	// identity is worse than none: a person's contacts without their conversations, under a
	// name the node would then refuse to import again. fn must use the Store it is given.
	Atomically(ctx context.Context, fn func(tx Store) error) error

	// Scrub makes what this store has deleted unreadable from its own files, where the engine can:
	// a leaf's key is destroyed, not only deleted (HDTP §9, SPEC §3.9). SQLite can, and does; on
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
	// InsertCredential inserts a credential, giving it a random id and the current time when it has
	// none. Kind must be one the table's CHECK admits (passkey, oauth, password), and an owner that
	// does not exist is refused by the foreign key.
	InsertCredential(ctx context.Context, c Credential) error
	// CountCredentialsByKind counts the credentials whose kind equals kind, across every owner. The
	// kind is not validated against the table's list, so an unknown kind counts 0.
	CountCredentialsByKind(ctx context.Context, kind string) (int64, error)
	// ListCredentialsByKind returns the credentials of one kind, across owners, ordered by creation
	// time and then id.
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
	// InsertSession inserts an owner session as given. The id is the primary key, and an owner that
	// does not exist is refused by the foreign key. The expiry is not checked here: GetSession
	// returns it, and DeleteExpiredSessions removes sessions past it.
	InsertSession(ctx context.Context, id, ownerID string, createdAt, expiresAt int64) error
	// GetSession returns the session's owner and expiry, or ErrNotFound. It does not compare the
	// expiry with the clock; the caller does.
	GetSession(ctx context.Context, id string) (ownerID string, expiresAt int64, err error)
	// RemoveSession deletes the session; one that is not there is not an error.
	RemoveSession(ctx context.Context, id string) error

	// DeleteExpiredSessions removes owner sessions past their time. Signing out deletes one and so
	// does presenting an expired one; an abandoned session is never presented again.
	DeleteExpiredSessions(ctx context.Context, now int64) (int64, error)
	// InsertToken inserts an owner-MCP token by the hash of its secret; an empty accountID stores
	// NULL, an owner-wide token.
	InsertToken(ctx context.Context, id, ownerID, label string, hash []byte, accountID string, createdAt int64) error
	// GetTokenByHash returns the owner-MCP token with this hash, revoked or not, or ErrNotFound.
	GetTokenByHash(ctx context.Context, hash []byte) (Token, error)
	// ListTokens returns every owner-MCP token, revoked ones included (RevokedAt is set), ordered by
	// creation time and then id.
	ListTokens(ctx context.Context) ([]Token, error)
	// RevokeToken stamps the token revoked at now; a token that is missing or already revoked is an
	// error.
	RevokeToken(ctx context.Context, id string, now int64) error
	// GetOwner returns the owner, or ErrNotFound.
	GetOwner(ctx context.Context, id string) (Owner, error)
	// ListOwners returns every owner ordered by creation time and then id.
	ListOwners(ctx context.Context) ([]Owner, error)
	// DeleteOwner deletes the owner; one that is not there is ErrNotFound.
	DeleteOwner(ctx context.Context, id string) error
	// AddMembership records that ownerID administers accountID with the given role. An owner or
	// account that does not exist is refused by the foreign keys.
	AddMembership(ctx context.Context, ownerID, accountID, role string) error
	// ListMembershipsByOwner returns the owner's memberships, ordered by account id.
	ListMembershipsByOwner(ctx context.Context, ownerID string) ([]Membership, error)
	// RemoveMembership removes the owner's membership of the account; one that is not there is
	// ErrNotFound.
	RemoveMembership(ctx context.Context, ownerID, accountID string) error
}

// AccountStore holds the identities this node answers for: the account rows, their keys, the HDTP
// root and leaf ledger, and a move's campaign (SPEC §3, HDTP §5.3, §9).
type AccountStore interface {
	// CreateAccount inserts an account under a fresh random id with the current time as CreatedAt and
	// returns the stored row. It runs in a transaction; a slug already taken is refused by the table's
	// constraint.
	CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error)

	// SetAccountKey binds the account's first key once: it refuses to overwrite an
	// existing fingerprint. A leaf install moves it, through SetAccountLeafKey.
	SetAccountKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte) error
	// GetAccountBySlug returns the account with this slug, or ErrNotFound.
	GetAccountBySlug(ctx context.Context, slug string) (Account, error)
	// ListAccounts returns every account ordered by creation time and then id.
	ListAccounts(ctx context.Context) ([]Account, error)
	// GetAccountByID returns the account, or ErrNotFound.
	GetAccountByID(ctx context.Context, id string) (Account, error)
	// GetAccountSealedKey returns the account's sealed leaf key. An account with no key returns nil
	// and a nil error: no key is a state, and each caller decides what it means.
	GetAccountSealedKey(ctx context.Context, id string) ([]byte, error)

	// UpdateAccountSeal sets the account's X-HDTP-SEAL policy (SPEC §4.6).
	UpdateAccountSeal(ctx context.Context, accountID, seal string) error
	// UpsertMoveFanout writes the progress of a move campaign for one contact, one row per account and
	// contact, stamped now when UpdatedAt is zero.
	UpsertMoveFanout(ctx context.Context, f MoveFanout) error
	// ListMoveFanout returns the account's move-campaign progress rows, ordered by contact
	// fingerprint.
	ListMoveFanout(ctx context.Context, accountID string) ([]MoveFanout, error)

	// HDTP 1.0: the account's root and leaf ledger. The pins, removal tombstones,
	// former endpoints and pending addresses are ContactStore's.
	SetAccountRoot(ctx context.Context, accountID, rootFingerprint string, rootCert []byte) error
	// SetAccountLeafKey points the account at its current leaf key: the fingerprint, the sealed key
	// and the algorithm. Unlike SetAccountKey it moves an existing key; an account that is not there
	// is an error.
	SetAccountLeafKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte, algo string) error
	// SetAccountHostPolicy sets the owner's accept_new_hosts setting (auto or ask) for the account; an
	// account that is not there is an error.
	SetAccountHostPolicy(ctx context.Context, accountID, acceptNewHosts string) error
	// InsertLeaf inserts a leaf row, stamped now when CreatedAt is zero. It writes the leaf's
	// certificate, sealed key, validity window, state and endpoint, and not the wallet request
	// columns, which SetLeafRequest owns. An account may hold only one pending leaf (the unique index
	// leaves_one_pending); a second is refused.
	InsertLeaf(ctx context.Context, l Leaf) error
	// UpdateLeaf rewrites a leaf's certificate, validity window, state and endpoint; a leaf that is
	// not there is an error.
	UpdateLeaf(ctx context.Context, l Leaf) error
	// SetLeafMoved records whether installing the leaf moved the identity; a leaf that is not there is
	// an error.
	SetLeafMoved(ctx context.Context, accountID, kid string, moved bool) error
	// ListLeaves returns every leaf row of the account, whatever its state, ordered by creation time
	// and then kid; an account with none yields an empty list.
	ListLeaves(ctx context.Context, accountID string) ([]Leaf, error)

	// ListKidsExcept is every leaf kid on this node that belongs to some OTHER
	// account. One inbound envelope needs it to tell a kid held for a sibling
	// identity from one this endpoint never held (HDTP §13.3, §14.4), and it is
	// one query rather than one per sibling: the per-account form made the cost
	// of every message grow with the number of identities the node hosts.
	ListKidsExcept(ctx context.Context, accountID string) ([]string, error)
	// RetireLeafKey destroys a superseded leaf's sealed key (it sets the column to NULL) and marks the
	// leaf former, keeping its kid so an envelope still sealed to it is answered certificate_renewed.
	// It does not report a leaf that is not there.
	RetireLeafKey(ctx context.Context, accountID, kid string) error

	// ClearAccountKey destroys the account's copy of its current leaf's key and keeps the
	// fingerprint. With RetireLeafKey it is what an expired leaf's key becomes: nothing.
	ClearAccountKey(ctx context.Context, accountID string) error
	// DeleteLeavesByState deletes the account's leaf rows whose state equals state (pending, current,
	// superseded or former) and returns how many went. Any other value matches nothing and returns 0.
	DeleteLeavesByState(ctx context.Context, accountID, state string) (int64, error)
	// LockAccount, inside Atomically, makes every other transaction that locks the same account
	// wait until this one ends: a signing request replacing the pending one is one step, never
	// two interleaved. SQLite's transactions are already one at a time.
	LockAccount(ctx context.Context, accountID string) error
	// SetLeafRequest and ConsumeLeafRequest hold a pending request's answer to one use (HDTP §9.1): the state's hash goes on with the request and comes off, in one statement
	// that also checks it, when an answer carrying it is installed. That statement keeps it as the
	// leaf's AnsweredStateHash.
	SetLeafRequest(ctx context.Context, accountID, kid string, stateHash []byte, walletOrigin string) error
	// ConsumeLeafRequest takes the state off the pending request for kid if, and only if, it is the
	// one given, keeps it as the leaf's AnsweredStateHash, and reports whether it did; false when the
	// request was never minted, carries another state, or was already used.
	ConsumeLeafRequest(ctx context.Context, accountID, kid string, stateHash []byte) (bool, error)

	// An identity leaving this host (HDTP §9, identity.Manager.Leave). DeleteAccount deletes the
	// account row and, by ON DELETE CASCADE, every row that names it by a foreign key;
	// DeleteTokensByAccount, DeleteIdempotencyByAccount and DeleteChangesByAccount are the tables
	// that name it without one.
	DeleteAccount(ctx context.Context, accountID string) (int64, error)
	// DeleteTokensByAccount deletes, rather than revokes, the tokens scoped to the account, so no row
	// goes on naming an identity that left.
	DeleteTokensByAccount(ctx context.Context, accountID string) (int64, error)
	// DeleteIdempotencyByAccount deletes the account's idempotency records, which have no foreign key
	// to cascade from.
	DeleteIdempotencyByAccount(ctx context.Context, accountID string) (int64, error)
	// DeleteChangesByAccount deletes every change row of one account, for an identity that left. Change
	// rows name the account without a foreign key, so DeleteAccount's cascade does not reach them.
	DeleteChangesByAccount(ctx context.Context, accountID string) (int64, error)
}

// InviteStore holds an account's invites (SPEC §9.2).
type InviteStore interface {
	// InsertInvite inserts an invite, defaulting its id, creation time and a MaxUses of zero to one,
	// and returns it.
	InsertInvite(ctx context.Context, inv Invite) (Invite, error)
	// GetInviteByHash returns the account's invite whose token hash is tokenHash, or ErrNotFound. It
	// does not look at expiry, revocation or uses.
	GetInviteByHash(ctx context.Context, accountID string, tokenHash []byte) (Invite, error)

	// GetInviteByHashGlobal resolves a landing-page token with no account in the
	// URL (SPEC §9.2 — /i/<token> carries only the bearer token).
	GetInviteByHashGlobal(ctx context.Context, tokenHash []byte) (Invite, error)
	// ListInvites returns the account's invites, revoked and spent ones included, ordered by
	// creation time and then id.
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
// §9, HDTP §5.3, §14.3).
type ContactStore interface {
	// SetContactPetname sets the owner's local name for a contact; "" clears it.
	SetContactPetname(ctx context.Context, accountID, fingerprint, petname string) error

	// UpdateContactCard rewrites a contact's card and display name once a card has
	// verified: a refresh the owner asked for (node.RefreshContact) or the peer's own
	// `update_contact`. The pinned root never changes here.
	UpdateContactCard(ctx context.Context, accountID, fingerprint, card, displayName string) error
	// UpsertTombstone inserts the account's tombstone for one root or, if it has one (the key is
	// account and root), replaces its leaf and time. At is stamped now when zero.
	UpsertTombstone(ctx context.Context, t Tombstone) error
	// ListTombstones returns the account's removal tombstones, ordered by time and then root.
	ListTombstones(ctx context.Context, accountID string) ([]Tombstone, error)
	// DeleteTombstone removes the tombstone of one root; one that is not there is not an error.
	DeleteTombstone(ctx context.Context, accountID, root string) error
	// InsertFormerEndpoint records where a pinned root used to answer, stamped now when At is zero.
	// The key is (account, root, endpoint, at): a root may have several former endpoints, and the
	// same endpoint recorded at the same instant twice is refused.
	InsertFormerEndpoint(ctx context.Context, f FormerEndpoint) error
	// ListFormerEndpoints returns the account's former endpoints ordered by time, then root, then
	// endpoint; an account with none yields an empty list.
	ListFormerEndpoints(ctx context.Context, accountID string) ([]FormerEndpoint, error)
	// UpsertPendingAddress inserts the address waiting under one root or, if there is one (the key
	// is account and root), replaces its endpoint, leaf, reason and time. A replacement without a
	// root certificate keeps the one already stored, because the root of a pending address cannot
	// change. At is stamped now when zero.
	UpsertPendingAddress(ctx context.Context, p PendingAddress) error
	// ListPendingAddresses returns the account's addresses waiting for the owner, ordered by time
	// and then root.
	ListPendingAddresses(ctx context.Context, accountID string) ([]PendingAddress, error)
	// GetPendingAddress returns the pending address of one root, or ErrNotFound.
	GetPendingAddress(ctx context.Context, accountID, root string) (PendingAddress, error)
	// DeletePendingAddress removes the pending address of one root; one that is not there is not an
	// error.
	DeletePendingAddress(ctx context.Context, accountID, root string) error
	// RepinContactAddress moves a contact's pin to a new endpoint, leaf and key, stamping PinnedAt,
	// and recomputes the leaf fingerprint with it. The root (the contact's fingerprint) never moves; a
	// contact that is not there is an error.
	RepinContactAddress(ctx context.Context, accountID, root, endpoint string, leaf, spki []byte, now int64) error

	// SetContactRootCert fills a pin's root certificate when it has none, and
	// leaves an existing one alone: the root of a pin cannot change (HDTP sec. 14.3).
	SetContactRootCert(ctx context.Context, accountID, root string, cert []byte) error
	// SetContactChainSentKid records which of this host's leaves was last carried to the contact; a
	// contact that is not there is an error.
	SetContactChainSentKid(ctx context.Context, accountID, fingerprint, kid string) error
	// ClearChainSentKids forgets, for every contact of the account, which of this host's leaves was
	// last carried to it, so the next leaf's chain is sent once to each (HDTP §13.2).
	ClearChainSentKids(ctx context.Context, accountID string) error
	// InsertContact inserts a contact, giving it a random id, the current time as CreatedAt,
	// ever_active for an active status and a request clock for pending_in and pending_out, and returns
	// the stored row.
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
	// GetContact returns the contact, or ErrNotFound.
	GetContact(ctx context.Context, accountID, fingerprint string) (Contact, error)
	// ListContacts returns the account's contacts ordered by creation time and id.
	ListContacts(ctx context.Context, accountID string) ([]Contact, error)
	// CountContactsByStatus counts one account's contacts in one state, reading those rows alone.
	CountContactsByStatus(ctx context.Context, accountID, status string) (int64, error)
	// PinCandidates is the contacts a sealed call's proof could concern, in ListContacts' order: the
	// row of `root`, the rows at `endpoint`, and the row whose pinned leaf's key has the fingerprint
	// `leafFingerprint`. An empty argument matches nothing. public/decide.go hands
	// these to Decide instead of every contact.
	PinCandidates(ctx context.Context, accountID, root, endpoint, leafFingerprint string) ([]Contact, error)
	// CountHeldContacts counts what an account holds against its contact cap: active contacts
	// and the requests it sent (pending_out).
	CountHeldContacts(ctx context.Context, accountID string) (int64, error)

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
	// request_contact, written before the request is sent (HDTP §9.2). False when the row changed.
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
	// THEY granted US (HDTP §6.2), and activates the relationship.
	SetContactAccepted(ctx context.Context, accountID, fingerprint, card string, theirPermissions []string, now int64) error

	// DeleteContact removes the row entirely (SPEC §9.1 `--> none`): the pin
	// and the relationship go, so re-adding starts fresh.
	DeleteContact(ctx context.Context, accountID, fingerprint string) error
	// UpdateContactPermissions sets what we granted the contact, as a permission list and a preset; a
	// contact that is not there is an error.
	UpdateContactPermissions(ctx context.Context, accountID, fingerprint string, permissions []string, preset string) error
	// UpdateContactTrust sets the contact's trust flag; a contact that is not there is an error.
	UpdateContactTrust(ctx context.Context, accountID, fingerprint, trustFlag string) error
}

// MessageStore holds conversations: threads, messages, media blobs, the idempotency records that
// make a call safe to repeat, and the local deletes retention makes (SPEC §7, §11.2).
type MessageStore interface {
	// InsertThread inserts a thread as given. The primary key is (account, id), so a thread id the
	// account already uses is refused by the table; ImportThread is the form that leaves an existing
	// thread as it is.
	InsertThread(ctx context.Context, t Thread) error
	// ImportThread, ImportMessage and ImportBlob write what an export carried (SPEC §3.10). Each
	// leaves a row that is already here as it is, so an import into an identity this host already
	// holds adds what it lacks and changes nothing it has; each reports whether it wrote.
	ImportThread(ctx context.Context, t Thread) (bool, error)
	// ImportMessage writes a message an export carried, keeping its id and giving it no retry
	// schedule, and reports whether it wrote; one already here by id or by the sender's msg_id is left
	// as it is.
	ImportMessage(ctx context.Context, m Message) (bool, error)
	// ImportBlob writes a blob record an export carried and reports whether it wrote; one already here
	// by hash is left as it is.
	ImportBlob(ctx context.Context, b Blob) (bool, error)
	// GetThread returns the account's thread, or ErrNotFound.
	GetThread(ctx context.Context, accountID, threadID string) (Thread, error)
	// TouchThread sets the thread's last activity time to lastAt, whatever it was: it can lower it.
	// It returns how many threads it touched, 0 when the thread is not there (deleted meanwhile).
	TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) (int64, error)
	// InsertMessage inserts a message, defaulting its id and an empty kind to "text". A msg_id already
	// taken in that direction of that conversation is refused by the table.
	InsertMessage(ctx context.Context, m Message) error

	// GetMessage returns the account's message by its id (not the sender's msg_id), or ErrNotFound.
	GetMessage(ctx context.Context, accountID, id string) (Message, error)
	// SetMediaBody rewrites a media message's description (a fetched URL now naming its file) and
	// returns how many rows changed: 0 when the account has no media message with that id.
	SetMediaBody(ctx context.Context, accountID, id, body string) (int64, error)

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
	// ListMessagesByThread returns a thread's messages in the order they were written (seq).
	ListMessagesByThread(ctx context.Context, accountID, threadID string) ([]Message, error)
	// InsertBlob inserts the account's record of an inline media file as given. A hash the account
	// already has is refused by the primary key (account, hash); ImportBlob is the form that leaves
	// an existing record as it is.
	InsertBlob(ctx context.Context, b Blob) error
	// GetBlob returns the account's blob record for hash, or ErrNotFound.
	GetBlob(ctx context.Context, accountID, hash string) (Blob, error)
	// OrphanSweepSince is when the orphan sweep began to judge files (unix seconds): the moment
	// migration 0003 ran. A record written before it is kept by the sweep (messaging.Sweeper).
	OrphanSweepSince(ctx context.Context) (int64, error)
	// MediaNames reports whether any media message of the account names the file.
	MediaNames(ctx context.Context, accountID, hash string) (bool, error)
	// LockFile, inside Atomically, makes every other transaction that locks the same file wait until
	// this one ends, across processes: storing a file and collecting it take turns. SQLite's
	// transactions are already one at a time.
	LockFile(ctx context.Context, hash string) error
	// SumBlobBytes returns the total size in bytes of the account's blob records, 0 when it has none.
	SumBlobBytes(ctx context.Context, accountID string) (int64, error)

	// Retention (SPEC §7.9). All of these delete LOCAL copies only: there is no
	// wire protocol for remote deletion, and the peer's copy is the peer's.
	DeleteMessagesBefore(ctx context.Context, accountID string, cutoff int64) (int64, error)
	// DeleteEmptyThreads deletes the account's threads that hold no message and returns how many went.
	// Empty is judged in the same account: a message of another account under the same thread id does
	// not keep the thread alive.
	DeleteEmptyThreads(ctx context.Context, accountID string) (int64, error)

	// Deleting one conversation (SPEC §7.9), local like retention. ListThreadMediaBodies returns the
	// bodies of one thread's media messages, oldest first: the files the deletion may leave
	// unreferenced. DeleteThreadMessages, DeleteThread and DeleteChangesByThread delete the thread's
	// messages, its row (read marker and kept names with it) and the change-log rows naming it, and
	// each returns how many rows went.
	ListThreadMediaBodies(ctx context.Context, accountID, threadID string) ([]string, error)
	DeleteThreadMessages(ctx context.Context, accountID, threadID string) (int64, error)
	DeleteThread(ctx context.Context, accountID, threadID string) (int64, error)
	DeleteChangesByThread(ctx context.Context, accountID, threadID string) (int64, error)

	// ListMediaBodies returns the bodies of an account's media messages, oldest first: what
	// retention reads to learn which media a retained message still references.
	ListMediaBodies(ctx context.Context, accountID string) ([]string, error)
	// ListBlobs returns the account's blob records ordered by creation time.
	ListBlobs(ctx context.Context, accountID string) ([]Blob, error)
	// DeleteBlob deletes the account's blob record for hash and returns how many rows went. It removes
	// the record, not the file.
	DeleteBlob(ctx context.Context, accountID, hash string) (int64, error)

	// CountBlobRefs counts rows for a hash ACROSS accounts: the blob store is
	// content-addressed, so the file may only be removed once nobody refers to it.
	CountBlobRefs(ctx context.Context, hash string) (int64, error)
	// ListThreadsByAccount returns the account's threads, most recently active first.
	ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error)
	// UnreadCount counts the inbound messages of one thread above its read marker.
	UnreadCount(ctx context.Context, accountID, threadID string) (int64, error)

	// Read state (SPEC §7.6): local, never wire-visible. The marker is threads.last_read_seq, a
	// high-water mark that is only ever raised; the count of what is unread is never stored, it
	// is read from the marker when it is asked for.
	//
	// MarkThreadReadThrough raises one thread's marker to `through`, the seq of the newest
	// message its reader was shown; MarkConversationReadThrough raises every thread of one
	// contact's. Each answers how many threads moved: 0 when nothing was unread through it.
	MarkThreadReadThrough(ctx context.Context, accountID, threadID string, through int64) (int64, error)
	// MarkConversationReadThrough raises the read marker of every thread with one contact to `through`
	// where it is lower, and returns how many threads moved. The marker is never lowered.
	MarkConversationReadThrough(ctx context.Context, accountID, contactFpr string, through int64) (int64, error)
	// ConversationHasMessage says whether `seq` is a message of this account's conversation with
	// this contact: the only thing a conversation's read marker may name.
	ConversationHasMessage(ctx context.Context, accountID, contactFpr string, seq int64) (bool, error)
	// UnreadWithContactUpTo counts a conversation's unread messages no further than upTo.
	UnreadWithContactUpTo(ctx context.Context, accountID, contactFpr string, upTo int) (int64, error)
	// ListContactsWithUnread is every contact with at least one unread message.
	ListContactsWithUnread(ctx context.Context, accountID string) ([]string, error)

	// Two callers share this table and MUST NOT share a key. An envelope's
	// replay guard reserves public.EnvelopeKey(msg_id); a tool that carries its
	// own msg_id (book_slot) reserves the bare one. They collided once —
	// call_contact sends the tool's msg_id as the envelope's, so a sealed
	// booking reserved the id as an envelope and then read its own reservation
	// as another attempt in flight. Any new caller needs a namespace of its own.
	//
	// PutIdempotency records msg_id's acknowledgment once (SPEC §11.2): the
	// first writer wins; every caller gets back the stored ack and whether it
	// pre-existed. expiresAt 0 writes an undated record, which the sweep removes once it is older
	// than UndatedIdempotencyWindow (DeleteExpiredIdempotency).
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
	// GetIntegration returns the account's integration by slug; an error wrapping ErrNotFound when
	// there is none.
	GetIntegration(ctx context.Context, accountID, slug string) (Integration, error)
	// GetIntegrationByID returns the integration by id; an error wrapping ErrNotFound when there is
	// none.
	GetIntegrationByID(ctx context.Context, id string) (Integration, error)
	// GetAccountIntegration returns the account's integration by id; an error wrapping ErrNotFound
	// when there is none, and the same error when the id names another account's. The two are not
	// told apart, so a door built on this cannot tell a caller whether an id exists.
	GetAccountIntegration(ctx context.Context, accountID, id string) (Integration, error)
	// ListIntegrations returns the account's integrations ordered by slug.
	ListIntegrations(ctx context.Context, accountID string) ([]Integration, error)
	// UpdateIntegrationStatus sets an integration's status and touches its update time; one that is
	// not there is an error wrapping ErrNotFound.
	UpdateIntegrationStatus(ctx context.Context, id, status string) error
	// UpdateIntegrationConfig rewrites an integration's transport, endpoint, command and auth kind;
	// one that is not there is an error wrapping ErrNotFound.
	UpdateIntegrationConfig(ctx context.Context, id, transport, endpoint, command, authKind string) error
	// DeleteIntegration deletes the integration by id; one that is not there is an error wrapping
	// ErrNotFound.
	DeleteIntegration(ctx context.Context, id string) error

	// InsertCatalog stores an immutable snapshot; Version must be Latest+1.
	InsertCatalog(ctx context.Context, c Catalog) (Catalog, error)
	// LatestCatalog returns the highest catalog version of an integration; an error wrapping
	// ErrNotFound when it has none.
	LatestCatalog(ctx context.Context, integrationID string) (Catalog, error)
	// GetCatalog returns one catalog version of an integration; an error wrapping ErrNotFound when
	// there is none.
	GetCatalog(ctx context.Context, integrationID string, version int64) (Catalog, error)

	// InsertExposure stores an immutable exposure set; Version must be Latest+1.
	InsertExposure(ctx context.Context, e Exposure) (Exposure, error)
	// LatestExposure returns the highest exposure version of an integration; an error wrapping
	// ErrNotFound when it has none.
	LatestExposure(ctx context.Context, integrationID string) (Exposure, error)
	// GetExposure returns one exposure version of an integration; an error wrapping ErrNotFound when
	// there is none.
	GetExposure(ctx context.Context, integrationID string, version int64) (Exposure, error)

	// Pending agent-answered requests (SPEC §6.8).
	InsertPendingRequest(ctx context.Context, p PendingRequest) (PendingRequest, error)
	// GetPendingRequest returns the pending request by id, or an error wrapping ErrNotFound. It
	// returns the row whatever its status or expiry.
	GetPendingRequest(ctx context.Context, id string) (PendingRequest, error)
	// GetAccountPendingRequest returns the account's pending request by id, whatever its status or
	// expiry; an error wrapping ErrNotFound when there is none, and the same error when the id names
	// another account's. The two are not told apart, so a door built on this cannot tell a caller
	// whether an id exists.
	GetAccountPendingRequest(ctx context.Context, accountID, id string) (PendingRequest, error)
	// ListOpenPendingRequests returns the account's open requests that expire after now, oldest first.
	ListOpenPendingRequests(ctx context.Context, accountID string, now int64) ([]PendingRequest, error)

	// AnswerPendingRequest closes the account's OPEN, unexpired row; reports whether it did. Another
	// account's row is not closed.
	AnswerPendingRequest(ctx context.Context, accountID, id, result string, answeredAt, now int64) (bool, error)

	// SetIntegrationSecret stores the keyring-sealed credential blob (SPEC §6.3).
	SetIntegrationSecret(ctx context.Context, id string, sealed []byte) error
	// GetIntegrationSecret returns the integration's keyring-sealed credential blob; an error wrapping
	// ErrNotFound when the integration is not there.
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
	// InsertAuditEvent inserts one audit row exactly as given, with an empty accountID stored as NULL.
	// It does not read the head or check the hashes: AppendAuditEvent is the path that extends the
	// chain.
	InsertAuditEvent(ctx context.Context, seq int64, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) error
	// LastAuditEvent returns the seq and hash of the newest audit row, or ErrNotFound for an empty
	// chain.
	LastAuditEvent(ctx context.Context) (seq int64, hash string, err error)
	// ListAuditEvents returns the whole trail ascending by seq, or only one actor's rows when
	// actorFilter is not empty. It is the trail as it is verified; ListAuditEventsPage is the trail as
	// it is read.
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
