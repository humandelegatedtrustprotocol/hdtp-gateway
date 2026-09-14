-- +goose Up
-- PACT 2.0 (SPEC §2, §14): the person is a certificate authority. An account
-- that has been upgraded holds a leaf the person's root issued; the root's
-- fingerprint is the identity, the leaf's key is what `kid` names, signs and
-- seals. `fingerprint`/`key_sealed` keep naming the CURRENT leaf key so every
-- path keyed by them is unchanged; the root is beside them.
ALTER TABLE accounts ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN root_fingerprint TEXT;
ALTER TABLE accounts ADD COLUMN root_cert BLOB;
ALTER TABLE accounts ADD COLUMN accept_new_hosts TEXT NOT NULL DEFAULT 'auto';
ALTER TABLE accounts ADD COLUMN accept_1x INTEGER NOT NULL DEFAULT 1;

-- A 2.0 pin is the root (in `fingerprint`), the endpoint and the latest leaf
-- accepted (PACT §14.3); `spki` is that leaf's key, what to seal to and verify
-- under. `chain_sent_kid` is OUR leaf kid last carried to this contact: the
-- chain rides in the envelope until it equals our current kid, the fingerprint
-- after (PACT §13.2).
ALTER TABLE contacts ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1;
ALTER TABLE contacts ADD COLUMN endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE contacts ADD COLUMN leaf BLOB;
ALTER TABLE contacts ADD COLUMN chain_sent_kid TEXT NOT NULL DEFAULT '';

-- Every leaf this host holds for an account: `pending` while a CSR awaits the
-- wallet, `current` (exactly one), `superseded` with its key kept until
-- not_after, `former` with the key destroyed and the kid kept so an envelope
-- sealed to it is answered certificate_renewed (PACT §14.4).
CREATE TABLE leaves (
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kid         TEXT NOT NULL,
    leaf        BLOB,
    key_sealed  BLOB,
    not_before  INTEGER NOT NULL DEFAULT 0,
    not_after   INTEGER NOT NULL DEFAULT 0,
    state       TEXT NOT NULL CHECK (state IN ('pending','current','superseded','former')),
    endpoint    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, kid)
);

-- PACT §5.3 "after a removal": the removed root and the leaf that removed it,
-- kept 30 days, so a returning root is asked about whatever the setting says.
CREATE TABLE tombstones (
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root        TEXT NOT NULL,
    leaf        BLOB NOT NULL,
    at          INTEGER NOT NULL,
    PRIMARY KEY (account_id, root)
);

-- Where a pinned root used to answer, for the address-claim rule (PACT §5, §6.1).
CREATE TABLE former_endpoints (
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root        TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    at          INTEGER NOT NULL,
    PRIMARY KEY (account_id, root, endpoint, at)
);

-- A contact at a new address awaiting the owner under `ask` (PACT §5.3).
CREATE TABLE pending_addresses (
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    root        TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    leaf        BLOB NOT NULL,
    why         TEXT NOT NULL,
    at          INTEGER NOT NULL,
    PRIMARY KEY (account_id, root)
);

-- +goose Down
DROP TABLE pending_addresses;
DROP TABLE former_endpoints;
DROP TABLE tombstones;
DROP TABLE leaves;
ALTER TABLE contacts DROP COLUMN chain_sent_kid;
ALTER TABLE contacts DROP COLUMN leaf;
ALTER TABLE contacts DROP COLUMN endpoint;
ALTER TABLE contacts DROP COLUMN protocol;
ALTER TABLE accounts DROP COLUMN accept_1x;
ALTER TABLE accounts DROP COLUMN accept_new_hosts;
ALTER TABLE accounts DROP COLUMN root_cert;
ALTER TABLE accounts DROP COLUMN root_fingerprint;
ALTER TABLE accounts DROP COLUMN protocol;
