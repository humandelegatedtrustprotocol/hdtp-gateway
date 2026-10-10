package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertThread inserts a thread as given. The primary key is (account, id), so a thread id the
// account already uses is refused by the table; ImportThread is the form that leaves an existing
// thread as it is.
func (s *SQLite) InsertThread(ctx context.Context, t Thread) error {
	return s.q.InsertThread(ctx, sqlitedb.InsertThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
}

// GetThread returns the account's thread, or ErrNotFound.
func (s *SQLite) GetThread(ctx context.Context, accountID, threadID string) (Thread, error) {
	r, err := s.q.GetThread(ctx, sqlitedb.GetThreadParams{AccountID: accountID, ID: threadID})
	if err != nil {
		return Thread{}, err
	}
	return Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt, KeptDisplayName: r.KeptDisplayName, KeptPetname: r.KeptPetname}, nil
}

// TouchThread sets the thread's last activity time to lastAt, whatever it was: it can lower it. It
// returns how many threads it touched: 0 when the thread is not there.
func (s *SQLite) TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) (int64, error) {
	return s.q.TouchThread(ctx, sqlitedb.TouchThreadParams{LastAt: lastAt, AccountID: accountID, ID: threadID})
}

// ListPendingOutbound returns outbound messages still awaiting delivery, oldest
// first — the retry sweeper's work list (SPEC §7.1).
func (s *SQLite) ListPendingOutbound(ctx context.Context, limit int32) ([]Message, error) {
	rows, err := s.q.ListPendingOutbound(ctx, int64(limit))
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
func (s *SQLite) SetMessageStatus(ctx context.Context, accountID, contactFpr, msgID, status string) error {
	n, err := s.q.SetMessageStatus(ctx, sqlitedb.SetMessageStatusParams{
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
func (s *SQLite) SetMessageAttempt(ctx context.Context, accountID, contactFpr, msgID string, attempts, nextAt int64) error {
	n, err := s.q.SetMessageAttempt(ctx, sqlitedb.SetMessageAttemptParams{
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
func (s *SQLite) InsertMessage(ctx context.Context, m Message) error {
	return s.q.InsertMessage(ctx, messageInsert(m))
}

// GetMessageByMsgID returns the message with this sender-chosen msg_id in one direction of one
// conversation, or ErrNotFound.
func (s *SQLite) GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error) {
	r, err := s.q.GetMessageByMsgID(ctx, sqlitedb.GetMessageByMsgIDParams{AccountID: accountID, ContactFpr: contactFpr, Direction: direction, MsgID: msgID})
	if err != nil {
		return Message{}, err
	}
	return messageFromRow(r), nil
}

// ListMessagesByThread returns a thread's messages in the order they were written (seq).
func (s *SQLite) ListMessagesByThread(ctx context.Context, accountID, threadID string) ([]Message, error) {
	rs, err := s.q.ListMessagesByThread(ctx, sqlitedb.ListMessagesByThreadParams{AccountID: accountID, ThreadID: threadID})
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(rs))
	for _, r := range rs {
		out = append(out, messageFromRow(r))
	}
	return out, nil
}

// InsertBlob inserts the account's record of an inline media file as given. A hash the account
// already has is refused by the primary key (account, hash); ImportBlob is the form that leaves an
// existing record as it is.
func (s *SQLite) InsertBlob(ctx context.Context, b Blob) error {
	return s.q.InsertBlob(ctx, sqlitedb.InsertBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
}

// GetBlob returns the account's blob record for hash, or ErrNotFound.
func (s *SQLite) GetBlob(ctx context.Context, accountID, hash string) (Blob, error) {
	r, err := s.q.GetBlob(ctx, sqlitedb.GetBlobParams{AccountID: accountID, Hash: hash})
	if err != nil {
		return Blob{}, err
	}
	return Blob{AccountID: r.AccountID, Hash: r.Hash, Size: r.Size, Mime: r.Mime, Filename: r.Filename, CreatedAt: r.CreatedAt}, nil
}

// SumBlobBytes returns the total size in bytes of the account's blob records, 0 when it has none.
func (s *SQLite) SumBlobBytes(ctx context.Context, accountID string) (int64, error) {
	v, err := s.q.SumBlobBytes(ctx, accountID)
	if err != nil {
		return 0, err
	}
	switch n := v.(type) {
	case int64:
		return n, nil
	case float64:
		return int64(n), nil
	default:
		return 0, nil
	}
}

func kindOrText(k string) string {
	if k == "" {
		return "text"
	}
	return k
}

// ListThreadsByAccount returns the account's threads, most recently active first.
func (s *SQLite) ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error) {
	rs, err := s.q.ListThreadsByAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Thread, 0, len(rs))
	for _, r := range rs {
		out = append(out, Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt, KeptDisplayName: r.KeptDisplayName, KeptPetname: r.KeptPetname})
	}
	return out, nil
}

// UnreadCount counts the inbound messages of one thread above its read marker.
func (s *SQLite) UnreadCount(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.UnreadCount(ctx, sqlitedb.UnreadCountParams{AccountID: accountID, ThreadID: threadID})
}

// MarkThreadReadThrough raises one thread's read marker to `through` when it is lower, and returns
// how many threads moved (0 or 1). The marker is never lowered.
func (s *SQLite) MarkThreadReadThrough(ctx context.Context, accountID, threadID string, through int64) (int64, error) {
	return s.q.MarkThreadReadThrough(ctx, sqlitedb.MarkThreadReadThroughParams{LastReadSeq: through, AccountID: accountID, ID: threadID, LastReadSeq_2: through})
}

// MarkConversationReadThrough raises the read marker of every thread with one contact to `through`
// where it is lower, and returns how many threads moved. The marker is never lowered.
func (s *SQLite) MarkConversationReadThrough(ctx context.Context, accountID, contactFpr string, through int64) (int64, error) {
	return s.q.MarkConversationReadThrough(ctx, sqlitedb.MarkConversationReadThroughParams{LastReadSeq: through, AccountID: accountID, ContactFpr: contactFpr, LastReadSeq_2: through})
}

// ConversationHasMessage reports whether seq is a message of this account's conversation with this
// contact; a message of another account or another contact is not.
func (s *SQLite) ConversationHasMessage(ctx context.Context, accountID, contactFpr string, seq int64) (bool, error) {
	n, err := s.q.ConversationHasMessage(ctx, sqlitedb.ConversationHasMessageParams{AccountID: accountID, ContactFpr: contactFpr, Seq: seq})
	return n > 0, err
}

// UnreadWithContactUpTo counts one conversation's unread inbound messages, stopping at upTo.
func (s *SQLite) UnreadWithContactUpTo(ctx context.Context, accountID, contactFpr string, upTo int) (int64, error) {
	return s.q.UnreadWithContactUpTo(ctx, sqlitedb.UnreadWithContactUpToParams{AccountID: accountID, ContactFpr: contactFpr, Limit: int64(upTo)})
}

// ListContactsWithUnread returns the fingerprints of the account's contacts that have at least one
// unread inbound message, never a count.
func (s *SQLite) ListContactsWithUnread(ctx context.Context, accountID string) ([]string, error) {
	return s.q.ListContactsWithUnread(ctx, accountID)
}

// ImportThread writes a thread an export carried and reports whether it wrote; one already here by
// id is left as it is.
func (s *SQLite) ImportThread(ctx context.Context, t Thread) (bool, error) {
	n, err := s.q.ImportThread(ctx, sqlitedb.ImportThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
	return n > 0, err
}

// ImportMessage writes a message an export carried, keeping its id and giving it no retry schedule,
// and reports whether it wrote; one already here by id or by the sender's msg_id is left as it is.
func (s *SQLite) ImportMessage(ctx context.Context, m Message) (bool, error) {
	n, err := s.q.ImportMessage(ctx, messageImport(m))
	return n > 0, err
}

// ImportBlob writes a blob record an export carried and reports whether it wrote; one already here
// by hash is left as it is.
func (s *SQLite) ImportBlob(ctx context.Context, b Blob) (bool, error) {
	n, err := s.q.ImportBlob(ctx, sqlitedb.ImportBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
	return n > 0, err
}

// GetMessage returns the account's message by its id, or ErrNotFound.
func (s *SQLite) GetMessage(ctx context.Context, accountID, id string) (Message, error) {
	r, err := s.q.GetMessage(ctx, sqlitedb.GetMessageParams{AccountID: accountID, ID: id})
	if err != nil {
		return Message{}, err
	}
	return messageFromRow(r), nil
}

// SetMediaBody rewrites a media message's description and returns how many rows it changed: 0 when
// the account has no media message with that id.
func (s *SQLite) SetMediaBody(ctx context.Context, accountID, id, body string) (int64, error) {
	return s.q.SetMediaBody(ctx, sqlitedb.SetMediaBodyParams{Body: body, AccountID: accountID, ID: id})
}

// ListThreadMediaBodies returns the bodies of one thread's media messages, oldest first.
func (s *SQLite) ListThreadMediaBodies(ctx context.Context, accountID, threadID string) ([]string, error) {
	return s.q.ListThreadMediaBodies(ctx, sqlitedb.ListThreadMediaBodiesParams{AccountID: accountID, ThreadID: threadID})
}

// DeleteThreadMessages deletes every message of one thread and returns how many went.
func (s *SQLite) DeleteThreadMessages(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.DeleteThreadMessages(ctx, sqlitedb.DeleteThreadMessagesParams{AccountID: accountID, ThreadID: threadID})
}

// DeleteThread deletes one thread row, its read marker and its kept names with it, and returns how
// many went (0 or 1).
func (s *SQLite) DeleteThread(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.DeleteThread(ctx, sqlitedb.DeleteThreadParams{AccountID: accountID, ID: threadID})
}

// MediaNames reports whether any media message of the account names the file.
func (s *SQLite) MediaNames(ctx context.Context, accountID, hash string) (bool, error) {
	n, err := s.q.CountMediaNaming(ctx, sqlitedb.CountMediaNamingParams{AccountID: accountID, Body: mediaNamingPattern(hash)})
	return n > 0, err
}

// LockFile is nothing on SQLite: its transactions are one at a time already.
func (s *SQLite) LockFile(context.Context, string) error { return nil }

// mediaNamingPattern is the LIKE pattern for a media body that names a file: the host writes the
// hash as `"hash":"<hex>"`, and a hash is lowercase hex, which LIKE reads literally.
func mediaNamingPattern(hash string) string { return `%"hash":"` + hash + `"%` }
