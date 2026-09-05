-- +goose Up
-- SPEC 7.1: an OUTBOUND message is not delivered when it is written. The old
-- CHECK set left no way to say "written, not yet sent", so every outbound row
-- claimed a delivery that had not happened. Postgres can replace the constraint
-- in place; existing rows keep their status.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human','pending','failed'));

-- +goose Down
UPDATE messages SET status = 'delivered' WHERE status IN ('pending','failed');
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human'));
