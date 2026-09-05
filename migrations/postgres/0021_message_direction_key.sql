-- +goose Up
-- SPEC 7.1: msg_id is the CALLER's idempotency key, so its scope is the caller.
-- Without direction in the key both sides share one namespace, and an outbound
-- message reusing a msg_id the contact already used was silently swallowed and
-- reported with the inbound row's status ("delivered"). See the sqlite twin for
-- the full account; Postgres can swap the constraint in place.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_account_id_contact_fpr_msg_id_key;
ALTER TABLE messages ADD CONSTRAINT messages_account_id_contact_fpr_direction_msg_id_key
    UNIQUE (account_id, contact_fpr, direction, msg_id);

-- +goose Down
-- Narrowing the key back can collide, because rows that are legitimate under the
-- wider key are duplicates under the narrower one. Drop the outbound side of any
-- such pair: the inbound row is evidence of what a peer actually sent.
DELETE FROM messages WHERE direction = 'out' AND EXISTS (
    SELECT 1 FROM messages m2 WHERE m2.account_id = messages.account_id
      AND m2.contact_fpr = messages.contact_fpr AND m2.msg_id = messages.msg_id
      AND m2.direction = 'in');
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_account_id_contact_fpr_direction_msg_id_key;
ALTER TABLE messages ADD CONSTRAINT messages_account_id_contact_fpr_msg_id_key
    UNIQUE (account_id, contact_fpr, msg_id);
