-- +goose Up
-- Owner asks and notices (docs/release/owner-asks-2026-10-19.md, N1).
--
-- An agent asks its owner something about one message of one thread (an ask), or tells them
-- something (a notice). `surface` is the A2UI v0.9.1 surface the agent wrote, held as JSON and
-- validated against the node's catalog before it is written (internal/services/asks). An ask is
-- open until it is answered, withdrawn or expires (`expires_at`, unix seconds); a notice is posted
-- and stays, with no expiry (0). `answer_text` is the one plain line an answer becomes. Times are
-- unix seconds, as a message's are. A row goes with its thread.
CREATE TABLE owner_asks (
    id text NOT NULL,
    account_id text NOT NULL,
    kind text NOT NULL,
    thread_id text NOT NULL,
    contact_fpr text NOT NULL,
    for_msg_id text NOT NULL,
    surface text NOT NULL,
    status text NOT NULL,
    answer_text text DEFAULT ''::text NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    expires_at bigint DEFAULT 0 NOT NULL,
    CONSTRAINT owner_asks_pkey PRIMARY KEY (id),
    CONSTRAINT owner_asks_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT owner_asks_kind_check CHECK (kind IN ('ask', 'notice')),
    CONSTRAINT owner_asks_status_check CHECK (status IN ('open', 'answered', 'expired', 'withdrawn', 'posted')),
    -- Asking twice about one message is one ask: the agent's retry finds the row it wrote.
    CONSTRAINT owner_asks_for_msg UNIQUE (account_id, kind, thread_id, for_msg_id)
);
-- One open ask per thread: a second is refused while the first is open.
CREATE UNIQUE INDEX owner_asks_open_thread ON owner_asks (account_id, thread_id) WHERE kind = 'ask' AND status = 'open';
CREATE INDEX owner_asks_account_created ON owner_asks (account_id, created_at);
CREATE INDEX owner_asks_contact ON owner_asks (account_id, contact_fpr, created_at);
-- The expiry sweep wants the open asks whose time has come, across accounts.
CREATE INDEX owner_asks_open_expiry ON owner_asks (expires_at) WHERE status = 'open';

-- +goose Down
DROP TABLE owner_asks;
