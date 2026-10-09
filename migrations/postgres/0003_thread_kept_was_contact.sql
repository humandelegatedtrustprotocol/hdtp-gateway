-- +goose Up
-- Whether a thread's root was ever a contact, kept as its contacts row is deleted (HDTP 9.2,
-- SEP-0004): an export carries the conversation of a former contact, and a stranger whose request
-- was never accepted, blocked or not, was never one. The row's ever_active, or its status active,
-- says so. Once kept it stays: the same root asking again and expiring, or rejected, does not
-- unmake a contact it once was. Threads whose row went before this migration keep 0: what their
-- row was is not recorded anywhere, so they stay with this host.
ALTER TABLE threads ADD COLUMN kept_was_contact integer DEFAULT 0 NOT NULL;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION contacts_keep_names_on_threads() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE threads SET kept_display_name = COALESCE(NULLIF(OLD.display_name, ''), kept_display_name),
        kept_petname = COALESCE(NULLIF(OLD.petname, ''), kept_petname),
        kept_was_contact = GREATEST(kept_was_contact, CASE WHEN OLD.ever_active = 1 OR OLD.status = 'active' THEN 1 ELSE 0 END)
    WHERE account_id = OLD.account_id AND contact_fpr = OLD.fingerprint;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION contacts_keep_names_on_threads() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE threads SET kept_display_name = COALESCE(NULLIF(OLD.display_name, ''), kept_display_name),
        kept_petname = COALESCE(NULLIF(OLD.petname, ''), kept_petname)
    WHERE account_id = OLD.account_id AND contact_fpr = OLD.fingerprint;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd
ALTER TABLE threads DROP COLUMN kept_was_contact;
