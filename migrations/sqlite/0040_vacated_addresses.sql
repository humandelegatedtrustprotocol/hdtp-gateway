-- +goose Up
-- An address an identity has left (PACT sec. 9, "What a host must do when the person leaves"): "An
-- address an identity has vacated MUST NOT be assigned to another identity until the last leaf
-- issued for it has expired." `account leave` erases the identity and writes one row per endpoint
-- its leaves named, with the latest not_after among them. The row holds the address and nothing
-- that names the identity: no account id, no root, no key, no leaf.
--
-- Two readers refuse while a row is live (until_at in the future): creating an account (any door:
-- the store's CreateAccount) with the slug, and a signing request (IssueCSR) for the endpoint. A
-- row past until_at protects nothing, and the hourly sweep deletes it.
CREATE TABLE vacated_addresses (
    endpoint TEXT PRIMARY KEY,
    slug     TEXT NOT NULL,
    until_at INTEGER NOT NULL,
    at       INTEGER NOT NULL
);
CREATE INDEX vacated_addresses_slug ON vacated_addresses(slug, until_at);

-- +goose Down
DROP TABLE vacated_addresses;
