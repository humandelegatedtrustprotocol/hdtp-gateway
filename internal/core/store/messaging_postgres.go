package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

func (s *Postgres) InsertThread(ctx context.Context, t Thread) error {
	return s.q.InsertThread(ctx, pgdb.InsertThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
}

func (s *Postgres) GetThread(ctx context.Context, accountID, threadID string) (Thread, error) {
	r, err := s.q.GetThread(ctx, pgdb.GetThreadParams{AccountID: accountID, ID: threadID})
	if err != nil {
		return Thread{}, err
	}
	return Thread{ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, Topic: r.Topic, CreatedAt: r.CreatedAt, LastAt: r.LastAt}, nil
}

func (s *Postgres) TouchThread(ctx context.Context, accountID, threadID string, lastAt int64) error {
	return s.q.TouchThread(ctx, pgdb.TouchThreadParams{LastAt: lastAt, AccountID: accountID, ID: threadID})
}

// SetMessageStatus records what became of a message after it was written. An
// outbound row starts `pending` and becomes `delivered` only when the peer
// actually accepted it (§7.1) — recording "delivered" at write time was a lie
// the portal told the owner.
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

func (s *Postgres) InsertMessage(ctx context.Context, m Message) error {
	return s.q.InsertMessage(ctx, pgdb.InsertMessageParams(messageInsert(m)))
}

func (s *Postgres) GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error) {
	r, err := s.q.GetMessageByMsgID(ctx, pgdb.GetMessageByMsgIDParams{AccountID: accountID, ContactFpr: contactFpr, Direction: direction, MsgID: msgID})
	if err != nil {
		return Message{}, err
	}
	return messageFromRow(sqlitedb.Message(r)), nil
}

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

func (s *Postgres) InsertBlob(ctx context.Context, b Blob) error {
	return s.q.InsertBlob(ctx, pgdb.InsertBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
}

func (s *Postgres) GetBlob(ctx context.Context, accountID, hash string) (Blob, error) {
	r, err := s.q.GetBlob(ctx, pgdb.GetBlobParams{AccountID: accountID, Hash: hash})
	if err != nil {
		return Blob{}, err
	}
	return Blob{AccountID: r.AccountID, Hash: r.Hash, Size: r.Size, Mime: r.Mime, Filename: r.Filename, CreatedAt: r.CreatedAt}, nil
}

func (s *Postgres) SumBlobBytes(ctx context.Context, accountID string) (int64, error) {
	// COALESCE(SUM(...), 0) types as a plain int64 here; the type switch this
	// replaced dated from a generated signature of `interface{}`.
	return s.q.SumBlobBytes(ctx, accountID)
}

func (s *Postgres) ListThreadsByAccount(ctx context.Context, accountID string) ([]Thread, error) {
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

func (s *Postgres) UnreadCount(ctx context.Context, accountID, threadID string) (int64, error) {
	return s.q.UnreadCount(ctx, pgdb.UnreadCountParams{AccountID: accountID, ThreadID: threadID})
}

func (s *Postgres) MarkThreadReadThrough(ctx context.Context, accountID, threadID string, through int64) (int64, error) {
	return s.q.MarkThreadReadThrough(ctx, pgdb.MarkThreadReadThroughParams{LastReadSeq: through, AccountID: accountID, ID: threadID})
}

func (s *Postgres) MarkConversationReadThrough(ctx context.Context, accountID, contactFpr string, through int64) (int64, error) {
	return s.q.MarkConversationReadThrough(ctx, pgdb.MarkConversationReadThroughParams{LastReadSeq: through, AccountID: accountID, ContactFpr: contactFpr})
}

func (s *Postgres) ConversationHasMessage(ctx context.Context, accountID, contactFpr string, seq int64) (bool, error) {
	n, err := s.q.ConversationHasMessage(ctx, pgdb.ConversationHasMessageParams{AccountID: accountID, ContactFpr: contactFpr, Seq: seq})
	return n > 0, err
}

func (s *Postgres) UnreadWithContactUpTo(ctx context.Context, accountID, contactFpr string, upTo int) (int64, error) {
	return s.q.UnreadWithContactUpTo(ctx, pgdb.UnreadWithContactUpToParams{AccountID: accountID, ContactFpr: contactFpr, Limit: pgLimit(upTo)})
}

func (s *Postgres) ListContactsWithUnread(ctx context.Context, accountID string) ([]string, error) {
	return s.q.ListContactsWithUnread(ctx, accountID)
}

func (s *Postgres) ImportThread(ctx context.Context, t Thread) (bool, error) {
	n, err := s.q.ImportThread(ctx, pgdb.ImportThreadParams{
		ID: t.ID, AccountID: t.AccountID, ContactFpr: t.ContactFpr,
		Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt,
	})
	return n > 0, err
}

func (s *Postgres) ImportMessage(ctx context.Context, m Message) (bool, error) {
	n, err := s.q.ImportMessage(ctx, pgdb.ImportMessageParams(messageImport(m)))
	return n > 0, err
}

func (s *Postgres) ImportBlob(ctx context.Context, b Blob) (bool, error) {
	n, err := s.q.ImportBlob(ctx, pgdb.ImportBlobParams{
		AccountID: b.AccountID, Hash: b.Hash, Size: b.Size, Mime: b.Mime,
		Filename: b.Filename, CreatedAt: b.CreatedAt,
	})
	return n > 0, err
}
