-- +goose Up
-- The owner's wait counts one account's contact requests awaiting approval on every wake
-- (CountContactsByStatus): with this index the count reads the rows in that state, not the
-- account's whole list.
CREATE INDEX contacts_account_status ON contacts(account_id, status);

-- +goose Down
DROP INDEX contacts_account_status;
