-- +goose Up
-- Whether a thread's root was ever a contact, kept as its contacts row is deleted (HDTP 9.2,
-- SEP-0004): an export carries the conversation of a former contact, and a stranger whose request
-- was never accepted, blocked or not, was never one. The row's ever_active, or its status active,
-- says so. Once kept it stays: the same root asking again and expiring, or rejected, does not
-- unmake a contact it once was. A thread written before this migration is kept as a contact's if it
-- holds a message: only a contact writes one, inbound at the contact tier (send_message, send_media
-- need an active row) and outbound to an active contact alone, and a request's note is kept on the
-- request, never as a message. A thread with no message left (retention took them) proves nothing,
-- keeps 0 and stays with this host, named as one with a root this host has no record of as a
-- contact.
ALTER TABLE threads ADD COLUMN kept_was_contact INTEGER NOT NULL DEFAULT 0;
UPDATE threads SET kept_was_contact = 1
    WHERE EXISTS (SELECT 1 FROM messages m WHERE m.account_id = threads.account_id AND m.thread_id = threads.id);
DROP TRIGGER contacts_keep_names_on_threads;
-- +goose StatementBegin
CREATE TRIGGER contacts_keep_names_on_threads BEFORE DELETE ON contacts
BEGIN
    UPDATE threads SET kept_display_name = COALESCE(NULLIF(OLD.display_name, ''), kept_display_name),
        kept_petname = COALESCE(NULLIF(OLD.petname, ''), kept_petname),
        kept_was_contact = MAX(kept_was_contact, CASE WHEN OLD.ever_active = 1 OR OLD.status = 'active' THEN 1 ELSE 0 END)
    WHERE account_id = OLD.account_id AND contact_fpr = OLD.fingerprint;
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER contacts_keep_names_on_threads;
-- +goose StatementBegin
CREATE TRIGGER contacts_keep_names_on_threads BEFORE DELETE ON contacts
BEGIN
    UPDATE threads SET kept_display_name = COALESCE(NULLIF(OLD.display_name, ''), kept_display_name),
        kept_petname = COALESCE(NULLIF(OLD.petname, ''), kept_petname)
    WHERE account_id = OLD.account_id AND contact_fpr = OLD.fingerprint;
END;
-- +goose StatementEnd
ALTER TABLE threads DROP COLUMN kept_was_contact;
