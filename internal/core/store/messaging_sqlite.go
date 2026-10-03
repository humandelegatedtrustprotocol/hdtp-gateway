package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func (s *SQLite) InsertThread(ctx context.Context, t Thread) error {
	return s.q.InsertThread(ctx, sqlitedb.InsertThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
}

func (s *SQLite) GetThread(ctx context.Context, accountID, threadID string) (Thread, error) {
	r, err := s.q.GetThread(ctx, sqlitedb.GetThreadParams{AccountID: accountID, ID: threadID})
	if err != nil {
		return Thread{}, err
	}
	return Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt}, nil
}

func (s *SQLite) TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) error {
	return s.q.TouchThread(ctx, sqlitedb.TouchThreadParams{LastAt: lastAt, AccountID: accountID, ID: threadID})
}

// SetMessageStatus records what became of a message after it was written. An
// outbound row starts `pending` and becomes `delivered` only when the peer
// actually accepted it (§7.1) — recording "delivered" at write time was a lie
// the portal told the owner.
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

func (s *SQLite) InsertMessage(ctx context.Context, m Message) error {
	return s.q.InsertMessage(ctx, messageInsert(m))
}

func (s *SQLite) GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error) {
	r, err := s.q.GetMessageByMsgID(ctx, sqlitedb.GetMessageByMsgIDParams{AccountID: accountID, ContactFpr: contactFpr, Direction: direction, MsgID: msgID})
	if err != nil {
		return Message{}, err
	}
	return messageFromRow(r), nil
}

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

func (s *SQLite) InsertBlob(ctx context.Context, b Blob) error {
	return s.q.InsertBlob(ctx, sqlitedb.InsertBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
}

func (s *SQLite) GetBlob(ctx context.Context, accountID, hash string) (Blob, error) {
	r, err := s.q.GetBlob(ctx, sqlitedb.GetBlobParams{AccountID: accountID, Hash: hash})
	if err != nil {
		return Blob{}, err
	}
	return Blob{AccountID: r.AccountID, Hash: r.Hash, Size: r.Size, Mime: r.Mime, Filename: r.Filename, CreatedAt: r.CreatedAt}, nil
}

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

func (s *SQLite) ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error) {
	rs, err := s.q.ListThreadsByAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Thread, 0, len(rs))
	for _, r := range rs {
		out = append(out, Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt})
	}
	return out, nil
}

func (s *SQLite) UnreadCount(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.UnreadCount(ctx, sqlitedb.UnreadCountParams{AccountID: accountID, ThreadID: threadID})
}

func (s *SQLite) MarkThreadReadThrough(ctx context.Context, accountID, threadID string, through int64) (int64, error) {
	return s.q.MarkThreadReadThrough(ctx, sqlitedb.MarkThreadReadThroughParams{LastReadSeq: through, AccountID: accountID, ID: threadID, LastReadSeq_2: through})
}

func (s *SQLite) MarkConversationReadThrough(ctx context.Context, accountID, contactFpr string, through int64) (int64, error) {
	return s.q.MarkConversationReadThrough(ctx, sqlitedb.MarkConversationReadThroughParams{LastReadSeq: through, AccountID: accountID, ContactFpr: contactFpr, LastReadSeq_2: through})
}

func (s *SQLite) ConversationHasMessage(ctx context.Context, accountID, contactFpr string, seq int64) (bool, error) {
	n, err := s.q.ConversationHasMessage(ctx, sqlitedb.ConversationHasMessageParams{AccountID: accountID, ContactFpr: contactFpr, Seq: seq})
	return n > 0, err
}

func (s *SQLite) UnreadWithContactUpTo(ctx context.Context, accountID, contactFpr string, upTo int) (int64, error) {
	return s.q.UnreadWithContactUpTo(ctx, sqlitedb.UnreadWithContactUpToParams{AccountID: accountID, ContactFpr: contactFpr, Limit: int64(upTo)})
}

func (s *SQLite) ListContactsWithUnread(ctx context.Context, accountID string) ([]string, error) {
	return s.q.ListContactsWithUnread(ctx, accountID)
}

func (s *SQLite) ImportThread(ctx context.Context, t Thread) (bool, error) {
	n, err := s.q.ImportThread(ctx, sqlitedb.ImportThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
	return n > 0, err
}

func (s *SQLite) ImportMessage(ctx context.Context, m Message) (bool, error) {
	n, err := s.q.ImportMessage(ctx, messageImport(m))
	return n > 0, err
}

func (s *SQLite) ImportBlob(ctx context.Context, b Blob) (bool, error) {
	n, err := s.q.ImportBlob(ctx, sqlitedb.ImportBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
	return n > 0, err
}
