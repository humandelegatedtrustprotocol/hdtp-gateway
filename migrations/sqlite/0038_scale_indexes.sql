-- +goose Up
-- The indexes a node needs once it is large. Every point lookup already rode a PRIMARY KEY or a
-- UNIQUE constraint; what did not were the statements that run on a TIMER, which read a whole
-- table to find the few rows they wanted, and the lists, which sorted every row they returned.
-- Measured at 10,000 contacts, 1,000,000 messages, 1,000,000 audit rows (internal/core/store/scale_test.go);
-- `TestEveryQueryHasAPlan` fails the build if a statement goes back to scanning.

-- The retry sweep (`ListPendingOutbound`) runs every tick and wants the handful of outbound rows
-- still pending, oldest first. A partial index holds exactly those rows, in that order, and costs
-- nothing for the other million: a row leaves it the moment it is delivered or fails.
CREATE INDEX messages_pending_out ON messages(seq) WHERE direction = 'out' AND status = 'pending';

-- Retention (`DeleteMessagesBefore`) asks for an account's messages older than a cutoff. It was
-- answered from `messages_thread`, by reading every message the account has.
CREATE INDEX messages_account_created ON messages(account_id, created_at);

-- Retention learns which media is still referenced from the media messages (`ListMediaBodies`),
-- one message in a hundred or fewer. Without this it read every message the account has.
CREATE INDEX messages_media ON messages(account_id, seq) WHERE kind = 'media';

-- `CountBlobRefs` counts a hash ACROSS accounts — the media store is content-addressed — and the
-- primary key leads with the account, so it walked the whole index.
CREATE INDEX blobs_hash ON blobs(hash);

-- One actor's trail (`ListAuditEventsByActor`, `ListAuditEventsPageByActor`), in chain order.
CREATE INDEX audit_events_actor ON audit_events(actor_id, seq);

-- The lists a portal page renders, in the order it renders them, so the order comes from the
-- index and not from a sort. `contacts_account` and `invites_account` are each a prefix of
-- their replacement.
DROP INDEX contacts_account;
CREATE INDEX contacts_account_created ON contacts(account_id, created_at, id);
CREATE INDEX threads_account_last ON threads(account_id, last_at DESC, id);
DROP INDEX invites_account;
CREATE INDEX invites_account_created ON invites(account_id, created_at, id);
CREATE INDEX blobs_account_created ON blobs(account_id, created_at);

-- The idempotency table takes a row for every sealed call and, until this migration, nothing ever
-- removed one. The hourly sweep now does, and finds them here: dated ones by their expiry,
-- undated ones, whose expiry is NULL, by their age.
CREATE INDEX idempotency_expiry ON idempotency(expires_at, created_at);

-- +goose Down
DROP INDEX idempotency_expiry;
DROP INDEX blobs_account_created;
DROP INDEX invites_account_created;
CREATE INDEX invites_account ON invites(account_id);
DROP INDEX threads_account_last;
DROP INDEX contacts_account_created;
CREATE INDEX contacts_account ON contacts(account_id);
DROP INDEX audit_events_actor;
DROP INDEX blobs_hash;
DROP INDEX messages_media;
DROP INDEX messages_account_created;
DROP INDEX messages_pending_out;
