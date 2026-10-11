-- +goose Up
-- A thread_id has two forms (HDTP 7, SEP-0006): 1 to 64 ASCII letters and digits, or a lower-case
-- UUID. A thread stored under any other id is deleted, with its messages, the files only they name,
-- its read marker and its change rows, and nothing is kept in its place. SQL cannot remove a file's
-- bytes, and the grammar has one implementation, the identity core's IsThreadID, so the deletion is
-- not here: this row schedules it, and serve runs it once, before it serves
-- (messaging.WipeThreadIDs), and then deletes the row.
CREATE TABLE thread_id_wipe (
    scheduled_at bigint NOT NULL
);
INSERT INTO thread_id_wipe (scheduled_at) VALUES (extract(epoch FROM now())::bigint);

-- +goose Down
DROP TABLE thread_id_wipe;
