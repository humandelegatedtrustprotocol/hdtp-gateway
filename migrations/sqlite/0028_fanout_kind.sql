-- +goose Up
-- HDTP 1.0 (HDTP §5.3, §9, Appendix C): the durable update_contact walk serves
-- three campaigns, resumed alike after an interruption — a 1.x key rotation,
-- a 2.0 move to a new address (the chain in the envelope is the proof), and
-- the 1.x rotation a 2.0 renewal with a fresh key is toward 1.x pins.
ALTER TABLE rotation_fanout ADD COLUMN kind TEXT NOT NULL DEFAULT 'rotation';

-- +goose Down
ALTER TABLE rotation_fanout DROP COLUMN kind;
