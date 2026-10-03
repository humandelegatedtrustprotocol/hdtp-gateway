-- +goose Up
-- The schema a node starts from. What each table holds is in SPEC.md sec. 11.2, which
-- internal/cli/doclint_test.go holds to the tables made here. The comments below say why an
-- index or a trigger exists.

CREATE TABLE owners (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('passkey','oauth','password')),
    tag TEXT NOT NULL DEFAULT '',
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX credentials_owner ON credentials(owner_id);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    hash BLOB NOT NULL UNIQUE,
    account_id TEXT,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    algo TEXT NOT NULL CHECK (algo IN ('p256','ed25519')),
    fingerprint TEXT UNIQUE,
    key_sealed BLOB,
    seal TEXT NOT NULL DEFAULT 'required' CHECK (seal IN ('none','optional','required')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at INTEGER NOT NULL,
    root_fingerprint TEXT,
    root_cert BLOB,
    accept_new_hosts TEXT NOT NULL DEFAULT 'auto'
);

CREATE TABLE memberships (
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
    PRIMARY KEY (owner_id, account_id)
);

CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    account_id TEXT,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('owner','token','contact','guest','cli','system')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    outcome TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
-- One actor's trail (ListAuditEventsByActor, ListAuditEventsPageByActor), in chain order.
CREATE INDEX audit_events_actor ON audit_events(actor_id, seq);
-- The hourly sweep asks which identities left long enough ago (ListDueLeaves): the few
-- account_leave rows among all the others, in chain order.
CREATE INDEX audit_events_leaves ON audit_events(seq) WHERE action = 'account_leave';
-- The audit trail is append-only: a row is never updated.
-- +goose StatementBegin
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
-- +goose StatementEnd
-- A row is deleted only once it is archived: a row the head anchor covers (audit_anchor), or a
-- row whose seq and hash are listed in audit_archive_rows. Every other DELETE is refused, so the
-- engine, not a convention in application code, stops rows being removed without a re-anchor.
-- +goose StatementBegin
CREATE TRIGGER audit_events_delete_only_archived BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events: only rows already archived and anchored may be pruned')
    WHERE NOT EXISTS (
        SELECT 1 FROM audit_anchor WHERE id = 1 AND archived_through_seq >= OLD.seq
    ) AND NOT EXISTS (
        SELECT 1 FROM audit_archive_rows WHERE seq = OLD.seq AND hash = OLD.hash
    );
END;
-- +goose StatementEnd

CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    spki BLOB,
    status TEXT NOT NULL CHECK (status IN ('active','pending_in','pending_out','blocked')),
    preset TEXT NOT NULL DEFAULT 'basic',
    permissions TEXT NOT NULL DEFAULT '["message.text"]',
    trust_flag TEXT NOT NULL DEFAULT 'messages_only' CHECK (trust_flag IN ('messages_only','may_instruct')),
    display_name TEXT NOT NULL DEFAULT '',
    card TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    pinned_at INTEGER,
    their_permissions TEXT NOT NULL DEFAULT '[]',
    petname TEXT NOT NULL DEFAULT '',
    invite_id TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    leaf BLOB,
    chain_sent_kid TEXT NOT NULL DEFAULT '',
    root_cert BLOB,
    ever_active INTEGER NOT NULL DEFAULT 0,
    handshake_due INTEGER NOT NULL DEFAULT 0,
    requested_at INTEGER,
    leaf_fingerprint TEXT,
    UNIQUE (account_id, fingerprint)
);
CREATE INDEX contacts_account_created ON contacts(account_id, created_at, id);
CREATE INDEX contacts_pending_requested ON contacts(account_id, requested_at) WHERE status IN ('pending_in', 'pending_out');
CREATE INDEX contacts_account_endpoint ON contacts(account_id, endpoint);
CREATE INDEX contacts_account_leaf_fingerprint ON contacts(account_id, leaf_fingerprint);
-- The owner's wait counts one account's contact requests awaiting approval on every wake
-- (CountContactsByStatus).
CREATE INDEX contacts_account_status ON contacts(account_id, status);

CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses INTEGER NOT NULL DEFAULT 0,
    auto_accept INTEGER NOT NULL DEFAULT 0,
    preset TEXT NOT NULL DEFAULT 'basic',
    permissions TEXT NOT NULL DEFAULT '["message.text"]',
    label TEXT NOT NULL DEFAULT '',
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX invites_account_created ON invites(account_id, created_at, id);

CREATE TABLE threads (
    id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    topic TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_at INTEGER NOT NULL,
    last_read_seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX threads_contact ON threads(account_id, contact_fpr);
CREATE INDEX threads_account_last ON threads(account_id, last_at DESC, id);

CREATE TABLE blobs (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    filename TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, hash)
);
-- CountBlobRefs counts a hash ACROSS accounts (the media store is content-addressed), and the
-- primary key leads with the account.
CREATE INDEX blobs_hash ON blobs(hash);
CREATE INDEX blobs_account_created ON blobs(account_id, created_at);

CREATE TABLE integrations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    transport TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    auth_kind TEXT NOT NULL DEFAULT 'none',
    status TEXT NOT NULL DEFAULT 'disabled',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    secret BLOB,
    UNIQUE (account_id, slug)
);

CREATE TABLE catalogs (
    id TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    tools TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (integration_id, version)
);

CREATE TABLE exposures (
    id TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    catalog_version INTEGER NOT NULL,
    entries TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (integration_id, version)
);

CREATE TABLE idempotency (
    account_id TEXT NOT NULL,
    contact_fpr TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    ack TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (account_id, contact_fpr, msg_id)
);
-- The hourly sweep removes spent rows and finds them here: dated ones by their expiry
-- (DeleteExpiredIdempotency), undated ones by their age (DeleteUndatedIdempotencyBefore).
CREATE INDEX idempotency_expiry ON idempotency(expires_at, created_at);

CREATE TABLE pending_requests (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    capability TEXT NOT NULL,
    args TEXT NOT NULL,
    trust_flag TEXT NOT NULL DEFAULT 'messages_only',
    status TEXT NOT NULL DEFAULT 'open',
    result TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    answered_at INTEGER
);
CREATE INDEX pending_account_status ON pending_requests(account_id, status);

CREATE TABLE move_fanout (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    leaf_kid TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, contact_fpr)
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    secret INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE audit_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    archived_through_seq INTEGER NOT NULL,
    terminal_hash TEXT NOT NULL,
    archive_path TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE leaves (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kid TEXT NOT NULL,
    leaf BLOB,
    key_sealed BLOB,
    not_before INTEGER NOT NULL DEFAULT 0,
    not_after INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL CHECK (state IN ('pending','current','superseded','former')),
    endpoint TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    request_state_hash BLOB,
    wallet_origin TEXT NOT NULL DEFAULT '',
    moved INTEGER NOT NULL DEFAULT 0,
    answered_state_hash BLOB,
    PRIMARY KEY (account_id, kid)
);
-- One pending signing request per identity (HDTP sec. 9.1): a new request replaces the last, and
-- a second pending row is impossible.
CREATE UNIQUE INDEX leaves_one_pending ON leaves(account_id) WHERE state = 'pending';

CREATE TABLE tombstones (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root TEXT NOT NULL,
    leaf BLOB NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (account_id, root)
);

CREATE TABLE former_endpoints (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (account_id, root, endpoint, at)
);

CREATE TABLE pending_addresses (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    leaf BLOB NOT NULL,
    why TEXT NOT NULL,
    at INTEGER NOT NULL,
    root_cert BLOB,
    PRIMARY KEY (account_id, root)
);

CREATE TABLE messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('in','out')),
    sender TEXT NOT NULL CHECK (sender IN ('agent','human')),
    body TEXT NOT NULL,
    reply_to TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human','pending','failed')),
    created_at INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media')),
    expires_at INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, contact_fpr, direction, msg_id)
);
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);
-- The retry sweep (ListPendingOutbound) runs every tick and wants the few outbound rows still
-- pending, oldest first. A partial index holds exactly those, and a row leaves it the moment it
-- is delivered or fails.
CREATE INDEX messages_pending_out ON messages(seq) WHERE direction = 'out' AND status = 'pending';
-- Retention (DeleteMessagesBefore) asks for an account's messages older than a cutoff.
CREATE INDEX messages_account_created ON messages(account_id, created_at);
-- Retention learns which media is still referenced from the media messages (ListMediaBodies).
CREATE INDEX messages_media ON messages(account_id, seq) WHERE kind = 'media';

CREATE TABLE vacated_addresses (
    endpoint TEXT PRIMARY KEY,
    slug TEXT NOT NULL,
    until_at INTEGER NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX vacated_addresses_slug ON vacated_addresses(slug, until_at);

CREATE TABLE audit_archive_rows (
    seq INTEGER PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE TABLE changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    thread_id TEXT NOT NULL DEFAULT '',
    contact_fpr TEXT NOT NULL DEFAULT '',
    ref TEXT NOT NULL DEFAULT '',
    at INTEGER NOT NULL
);
CREATE INDEX changes_at ON changes(at);
-- wait_for_updates reads one account's changes after its cursor.
CREATE INDEX changes_account ON changes(account_id, id);

CREATE TABLE owner_presence (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seen_at INTEGER NOT NULL
);

CREATE TABLE leases (
    name TEXT PRIMARY KEY,
    holder TEXT NOT NULL,
    taken_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE leases;
DROP TABLE owner_presence;
DROP TABLE changes;
DROP TABLE audit_archive_rows;
DROP TABLE vacated_addresses;
DROP TABLE messages;
DROP TABLE pending_addresses;
DROP TABLE former_endpoints;
DROP TABLE tombstones;
DROP TABLE leaves;
DROP TABLE audit_anchor;
DROP TABLE settings;
DROP TABLE move_fanout;
DROP TABLE pending_requests;
DROP TABLE idempotency;
DROP TABLE exposures;
DROP TABLE catalogs;
DROP TABLE integrations;
DROP TABLE blobs;
DROP TABLE threads;
DROP TABLE invites;
DROP TABLE contacts;
DROP TABLE audit_events;
DROP TABLE memberships;
DROP TABLE accounts;
DROP TABLE tokens;
DROP TABLE sessions;
DROP TABLE credentials;
DROP TABLE owners;
