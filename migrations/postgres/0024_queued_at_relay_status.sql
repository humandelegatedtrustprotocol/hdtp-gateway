-- +goose Up
-- SPEC 7.1: handing a message to the contact's relay is a FALLBACK, not an
-- arrival — see the sqlite twin. Postgres can replace the constraint in place.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human','pending','failed','queued_at_relay'));

-- +goose Down
UPDATE messages SET status = 'delivered' WHERE status = 'queued_at_relay';
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human','pending','failed'));
