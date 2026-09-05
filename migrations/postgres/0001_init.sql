-- +goose Up
CREATE TABLE owners (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at   BIGINT NOT NULL
);

CREATE TABLE credentials (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('passkey','oauth','password')),
    tag          TEXT NOT NULL DEFAULT '',
    data         BYTEA NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX credentials_owner ON credentials(owner_id);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    hash       BYTEA NOT NULL UNIQUE,
    account_id TEXT,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE TABLE accounts (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    algo         TEXT NOT NULL CHECK (algo IN ('p256','ed25519')),
    fingerprint  TEXT UNIQUE,
    key_sealed   BYTEA,
    seal         TEXT NOT NULL DEFAULT 'required' CHECK (seal IN ('none','optional','required')),
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at   BIGINT NOT NULL
);

CREATE TABLE memberships (
    owner_id   TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
    PRIMARY KEY (owner_id, account_id)
);

CREATE TABLE audit_events (
    seq        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         BIGINT NOT NULL,
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

-- SPEC §11.4: append-only enforced by the engine.
-- +goose StatementBegin
CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- +goose Down
DROP TRIGGER audit_events_no_delete ON audit_events;
DROP TRIGGER audit_events_no_update ON audit_events;
DROP FUNCTION audit_events_immutable;
DROP TABLE audit_events;
DROP TABLE memberships;
DROP TABLE accounts;
DROP TABLE tokens;
DROP TABLE sessions;
DROP TABLE credentials;
DROP TABLE owners;
