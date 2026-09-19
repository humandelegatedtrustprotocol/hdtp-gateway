-- +goose Up
-- rotation_fanout.kind told three campaigns apart (0028): a 1.x key rotation, the 1.x rotation a
-- 2.0 renewal was toward key-pinned contacts, and a 2.0 move. The first two went with 1.x. One
-- writer was left, which always wrote 'move', and no reader at all - progress is matched by
-- contact and by the leaf being announced - while both engines still defaulted an empty kind to
-- 'rotation'. A column that can hold one value holds none.
--
-- Rows of the retired kinds go first. They are progress toward announcements nobody will make
-- again, and once the column is gone nothing could tell them from a move's.
DELETE FROM rotation_fanout WHERE kind <> 'move';
ALTER TABLE rotation_fanout DROP COLUMN kind;

-- +goose Down
-- As 0028 made it, but defaulting to the only kind a surviving row can be, so 0028's own Down
-- still finds the column it drops.
ALTER TABLE rotation_fanout ADD COLUMN kind TEXT NOT NULL DEFAULT 'move';
