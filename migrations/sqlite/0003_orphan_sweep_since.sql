-- +goose Up
-- The hourly orphan sweep (messaging.Sweeper.CollectOrphans) takes a file no message names. Before
-- this migration a link the owner fetched was stored without being recorded on its message, so a
-- node upgraded from then holds files nothing names that are the owner's: content behind a link
-- that may be dead now. Their records carry no link to name them by, so they are kept: the sweep
-- judges only records written at or after the moment this migration ran, which it reads here.
CREATE TABLE orphan_sweep (
    since INTEGER NOT NULL
);
INSERT INTO orphan_sweep (since) VALUES (CAST(strftime('%s', 'now') AS INTEGER));

-- +goose Down
DROP TABLE orphan_sweep;
