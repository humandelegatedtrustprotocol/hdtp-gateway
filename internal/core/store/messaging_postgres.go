package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertThread inserts a thread as given. The primary key is (account, id), so a thread id the
// account already uses is refused by the table; ImportThread is the form that leaves an existing
// thread as it is.
func (s *Postgres) InsertThread(ctx context.Context, t Thread) error {
	return s.q.InsertThread(ctx, pgdb.InsertThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
}

// GetThread returns the account's thread, or ErrNotFound.
func (s *Postgres) GetThread(ctx context.Context, accountID, threadID string) (Thread, error) {
	r, err := s.q.GetThread(ctx, pgdb.GetThreadParams{AccountID: accountID, ID: threadID})
	if err != nil {
		return Thread{}, err
	}
	return Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt, KeptDisplayName: r.KeptDisplayName, KeptPetname: r.KeptPetname, KeptWasContact: r.KeptWasContact == 1}, nil
}

// TouchThread sets the thread's last activity time to lastAt, whatever it was: it can lower it, and
// a thread that is not there is not reported.
func (s *Postgres) TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) error {
	return s.q.TouchThread(ctx, pgdb.TouchThreadParams{LastAt: lastAt, AccountID: accountID, ID: threadID})
}

// ListPendingOutbound returns outbound messages still awaiting delivery, oldest
// first — the retry sweeper's work list (SPEC §7.1).
func (s *Postgres) ListPendingOutbound(ctx context.Context, limit int32) ([]Message, error) {
	rows, err := s.q.ListPendingOutbound(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(rows))
	for _, r := range rows {
		out = append(out, Message{
			Seq: r.Seq, ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr,
			MsgID: r.MsgID, ThreadID: r.ThreadID, Direction: r.Direction, Sender: r.Sender,
			Kind: r.Kind, Body: r.Body, ReplyTo: r.ReplyTo, Status: r.Status,
			CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
			Attempts: r.Attempts, NextAttemptAt: r.NextAttemptAt,
		})
	}
	return out, nil
}

// SetMessageStatus records what became of a message after it was written. Only outbound rows are
// touched, and a message that is not there is ErrNotFound.
func (s *Postgres) SetMessageStatus(ctx context.Context, accountID, contactFpr, msgID, status string) error {
	n, err := s.q.SetMessageStatus(ctx, pgdb.SetMessageStatusParams{
		Status: status, AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetMessageAttempt records a delivery attempt and when the next one is due.
func (s *Postgres) SetMessageAttempt(ctx context.Context, accountID, contactFpr, msgID string, attempts, nextAt int64) error {
	n, err := s.q.SetMessageAttempt(ctx, pgdb.SetMessageAttemptParams{
		Attempts: attempts, NextAttemptAt: nextAt,
		AccountID: accountID, ContactFpr: contactFpr, MsgID: msgID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// InsertMessage inserts a message, defaulting its id and an empty kind to "text". A msg_id already
// taken in that direction of that conversation is refused by the table.
func (s *Postgres) InsertMessage(ctx context.Context, m Message) error {
	return s.q.InsertMessage(ctx, pgdb.InsertMessageParams(messageInsert(m)))
}

// GetMessageByMsgID returns the message with this sender-chosen msg_id in one direction of one
// conversation, or ErrNotFound.
func (s *Postgres) GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error) {
	r, err := s.q.GetMessageByMsgID(ctx, pgdb.GetMessageByMsgIDParams{AccountID: accountID, ContactFpr: contactFpr, Direction: direction, MsgID: msgID})
	if err != nil {
		return Message{}, err
	}
	return messageFromRow(sqlitedb.Message(r)), nil
}

// ListMessagesByThread returns a thread's messages in the order they were written (seq).
func (s *Postgres) ListMessagesByThread(ctx context.Context, accountID, threadID string) ([]Message, error) {
	rs, err := s.q.ListMessagesByThread(ctx, pgdb.ListMessagesByThreadParams{AccountID: accountID, ThreadID: threadID})
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(rs))
	for _, r := range rs {
		out = append(out, messageFromRow(sqlitedb.Message(r)))
	}
	return out, nil
}

// InsertBlob inserts the account's record of an inline media file as given. A hash the account
// already has is refused by the primary key (account, hash); ImportBlob is the form that leaves an
// existing record as it is.
func (s *Postgres) InsertBlob(ctx context.Context, b Blob) error {
	return s.q.InsertBlob(ctx, pgdb.InsertBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
}

// GetBlob returns the account's blob record for hash, or ErrNotFound.
func (s *Postgres) GetBlob(ctx context.Context, accountID, hash string) (Blob, error) {
	r, err := s.q.GetBlob(ctx, pgdb.GetBlobParams{AccountID: accountID, Hash: hash})
	if err != nil {
		return Blob{}, err
	}
	return Blob{AccountID: r.AccountID, Hash: r.Hash, Size: r.Size, Mime: r.Mime, Filename: r.Filename, CreatedAt: r.CreatedAt}, nil
}

// SumBlobBytes returns the total size in bytes of the account's blob records, 0 when it has none.
func (s *Postgres) SumBlobBytes(ctx context.Context, accountID string) (int64, error) {
	// COALESCE(SUM(...), 0) types as a plain int64 here; the type switch this
	// replaced dated from a generated signature of `interface{}`.
	return s.q.SumBlobBytes(ctx, accountID)
}

// ListThreadsByAccount returns the account's threads, most recently active first.
func (s *Postgres) ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error) {
	rs, err := s.q.ListThreadsByAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Thread, 0, len(rs))
	for _, r := range rs {
		out = append(out, Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt, KeptDisplayName: r.KeptDisplayName, KeptPetname: r.KeptPetname, KeptWasContact: r.KeptWasContact == 1})
	}
	return out, nil
}

// UnreadCount counts the inbound messages of one thread above its read marker.
func (s *Postgres) UnreadCount(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.UnreadCount(ctx, pgdb.UnreadCountParams{AccountID: accountID, ThreadID: threadID})
}

// MarkThreadReadThrough raises one thread's read marker to `through` when it is lower, and returns
// how many threads moved (0 or 1). The marker is never lowered.
func (s *Postgres) MarkThreadReadThrough(ctx context.Context, accountID, threadID string, through int64) (int64, error) {
	return s.q.MarkThreadReadThrough(ctx, pgdb.MarkThreadReadThroughParams{LastReadSeq: through, AccountID: accountID, ID: threadID})
}

// MarkConversationReadThrough raises the read marker of every thread with one contact to `through`
// where it is lower, and returns how many threads moved. The marker is never lowered.
func (s *Postgres) MarkConversationReadThrough(ctx context.Context, accountID, contactFpr string, through int64) (int64, error) {
	return s.q.MarkConversationReadThrough(ctx, pgdb.MarkConversationReadThroughParams{LastReadSeq: through, AccountID: accountID, ContactFpr: contactFpr})
}

// ConversationHasMessage reports whether seq is a message of this account's conversation with this
// contact; a message of another account or another contact is not.
func (s *Postgres) ConversationHasMessage(ctx context.Context, accountID, contactFpr string, seq int64) (bool, error) {
	n, err := s.q.ConversationHasMessage(ctx, pgdb.ConversationHasMessageParams{AccountID: accountID, ContactFpr: contactFpr, Seq: seq})
	return n > 0, err
}

// UnreadWithContactUpTo counts one conversation's unread inbound messages, stopping at upTo.
func (s *Postgres) UnreadWithContactUpTo(ctx context.Context, accountID, contactFpr string, upTo int) (int64, error) {
	return s.q.UnreadWithContactUpTo(ctx, pgdb.UnreadWithContactUpToParams{AccountID: accountID, ContactFpr: contactFpr, Limit: pgLimit(upTo)})
}

// ListContactsWithUnread returns the fingerprints of the account's contacts that have at least one
// unread inbound message, never a count.
func (s *Postgres) ListContactsWithUnread(ctx context.Context, accountID string) ([]string, error) {
	return s.q.ListContactsWithUnread(ctx, accountID)
}

// ImportThread writes a thread an export carried and reports whether it wrote; one already here by
// id is left as it is.
func (s *Postgres) ImportThread(ctx context.Context, t Thread) (bool, error) {
	n, err := s.q.ImportThread(ctx, pgdb.ImportThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
		KeptDisplayName: t.KeptDisplayName, KeptPetname: t.KeptPetname, KeptWasContact: b2i(t.KeptWasContact),
	})
	return n > 0, err
}

// ImportMessage writes a message an export carried, keeping its id and giving it no retry schedule,
// and reports whether it wrote; one already here by id or by the sender's msg_id is left as it is.
func (s *Postgres) ImportMessage(ctx context.Context, m Message) (bool, error) {
	n, err := s.q.ImportMessage(ctx, pgdb.ImportMessageParams(messageImport(m)))
	return n > 0, err
}

// ImportBlob writes a blob record an export carried and reports whether it wrote; one already here
// by hash is left as it is.
func (s *Postgres) ImportBlob(ctx context.Context, b Blob) (bool, error) {
	n, err := s.q.ImportBlob(ctx, pgdb.ImportBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
	return n > 0, err
}
