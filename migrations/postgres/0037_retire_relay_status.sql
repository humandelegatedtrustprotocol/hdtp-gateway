-- +goose Up
-- The last of the relay: a delivery state nothing can write and nothing can resolve.
--
-- 0024 gave an outbound message a fourth state for "handed to the contact's store-and-forward
-- relay": a fallback, not an arrival, because a relay is a third party holding ciphertext for a
-- peer who may never collect it. The relay role went with pre-HDTP 1.x (0030 dropped its tables), and
-- the state outlived it: no code writes it, the retry sweep reads `pending` and so never touches
-- such a row, and the portal went on labelling it "queued at their relay" about a relay that does
-- not exist.
--
-- A row still in that state was never confirmed delivered and never can be. `failed` is what is
-- known about it — 0024's own argument against calling it `delivered`, which its Down did anyway.
UPDATE messages SET status = 'failed' WHERE status = 'queued_at_relay';
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human','pending','failed'));

-- +goose Down
-- The state comes back as something the CHECK allows; no row is put back INTO it, because
-- which rows were in it is exactly what Up decided could not be known.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_status_check
    CHECK (status IN ('delivered','queued_for_human','pending','failed','queued_at_relay'));
