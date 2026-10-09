-- +goose Up
-- A removed contact's conversation stays (a removal deletes the contacts row, not its threads),
-- and so does what the owner called them: the row's display_name and petname are copied onto each
-- of its threads as the row is deleted. A thread is "removed" when no contacts row names its
-- fingerprint; these two columns are only what it is labelled with then. A contact added again is
-- named by its row, and the next deletion writes them anew -- but an empty name never replaces a
-- kept one: a removed contact who asks again arrives as a request with no petname, and a request
-- rejected or expired must not erase what the owner called them.
ALTER TABLE threads ADD COLUMN kept_display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE threads ADD COLUMN kept_petname TEXT NOT NULL DEFAULT '';
-- A trigger, not a statement beside each DELETE: a row leaves by the owner's removal, the peer's
-- remove notice, an unblock's forget and a request's expiry, and the engine catches all of them.
-- +goose StatementBegin
CREATE TRIGGER contacts_keep_names_on_threads BEFORE DELETE ON contacts
BEGIN
    UPDATE threads SET kept_display_name = COALESCE(NULLIF(OLD.display_name, ''), kept_display_name),
        kept_petname = COALESCE(NULLIF(OLD.petname, ''), kept_petname)
    WHERE account_id = OLD.account_id AND contact_fpr = OLD.fingerprint;
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER contacts_keep_names_on_threads;
ALTER TABLE threads DROP COLUMN kept_petname;
ALTER TABLE threads DROP COLUMN kept_display_name;
