package store

import (
	"context"
	"database/sql"

	"github.com/tech-sumit/pact-gateway/internal/core/store/pgdb"
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
	if m.ID == "" {
		m.ID = newID()
	}
	return s.q.InsertMessage(ctx, pgdb.InsertMessageParams{
		ID: m.ID, AccountID: m.AccountID, ContactFpr: m.ContactFpr, MsgID: m.MsgID,
		ThreadID: m.ThreadID, Direction: m.Direction, Sender: m.Sender, Kind: kindOrText(m.Kind), Body: m.Body,
		ReplyTo: m.ReplyTo, Status: m.Status, CreatedAt: m.CreatedAt, ExpiresAt: m.ExpiresAt,
	})
}

func (s *Postgres) GetMessageByMsgID(ctx context.Context, accountID, contactFpr, direction, msgID string) (Message, error) {
	r, err := s.q.GetMessageByMsgID(ctx, pgdb.GetMessageByMsgIDParams{AccountID: accountID, ContactFpr: contactFpr, Direction: direction, MsgID: msgID})
	if err != nil {
		return Message{}, err
	}
	return pgMessage(r), nil
}

func pgMessage(r pgdb.Message) Message {
	return Message{
		Seq: r.Seq, ID: r.ID, AccountID: r.AccountID, ContactFpr: r.ContactFpr, MsgID: r.MsgID,
		ThreadID: r.ThreadID, Direction: r.Direction, Sender: r.Sender, Kind: r.Kind, Body: r.Body,
		ReplyTo: r.ReplyTo, Status: r.Status, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, Attempts: r.Attempts, NextAttemptAt: r.NextAttemptAt,
	}
}

func (s *Postgres) ListMessagesByThread(ctx context.Context, accountID, threadID string) ([]Message, error) {
	rs, err := s.q.ListMessagesByThread(ctx, pgdb.ListMessagesByThreadParams{AccountID: accountID, ThreadID: threadID})
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(rs))
	for _, r := range rs {
		out = append(out, pgMessage(r))
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

func (s *Postgres) MarkThreadRead(ctx context.Context, accountID, threadID string) error {
	_, err := s.q.MarkThreadRead(ctx, pgdb.MarkThreadReadParams{AccountID: accountID, ThreadID: threadID, AccountID_2: accountID, ID: threadID})
	return err
}
