-- +goose Up
CREATE TABLE owners (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

-- SPEC §3.1: passkeys now; oauth/password shaped for later.
CREATE TABLE credentials (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('passkey','oauth','password')),
    tag          TEXT NOT NULL DEFAULT '',
    data         BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX credentials_owner ON credentials(owner_id);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- SPEC §3.4: named revocable bearer tokens; hash only, never the secret.
CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    account_id TEXT,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

-- SPEC §3.2: an account is an identity; key material sealed by the keyring (§3.7).
CREATE TABLE accounts (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    algo         TEXT NOT NULL CHECK (algo IN ('p256','ed25519')),
    fingerprint  TEXT UNIQUE,
    key_sealed   BLOB,
    seal         TEXT NOT NULL DEFAULT 'required' CHECK (seal IN ('none','optional','required')),
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at   INTEGER NOT NULL
);

-- SPEC §3.3: many-to-many, single 'admin' role in v1, column pre-shaped for more.
CREATE TABLE memberships (
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
    PRIMARY KEY (owner_id, account_id)
);

-- SPEC §11.4: append-only hash chain; UPDATE/DELETE are refused by triggers so the
-- chain property is enforced by the engine, not by convention.
CREATE TABLE audit_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    account_id TEXT,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('owner','token','contact','guest','cli','system')),
    actor_id   TEXT NOT NULL,
    action     TEXT NOT NULL,
    resource   TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT '{}',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);

-- +goose StatementBegin
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_events_no_delete;
DROP TRIGGER audit_events_no_update;
DROP TABLE audit_events;
DROP TABLE memberships;
DROP TABLE accounts;
DROP TABLE tokens;
DROP TABLE sessions;
DROP TABLE credentials;
DROP TABLE owners;
