// Package messaging implements threads and messages (SPEC §7, HDTP §6.2/§7):
// shared thread ids, strict msg_id idempotency (acknowledged, never re-executed),
// the 16 KiB text cap, and sender labels that are typed constants — derived from
// the originating surface by callers, never accepted as free-form input.
package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Wire error codes this package returns, wrapped with a detail after a colon (HDTP section 12):
// ErrTooLarge for text over 16 KiB, a topic over 256 bytes, or media over its caps; ErrBadRequest
// for a missing msg_id, a missing or invalid origin or sender, a thread of another contact, or a
// topic given for a thread that exists.
var (
	ErrTooLarge   = errors.New("too_large")
	ErrBadRequest = errors.New("bad_request")
)

// Sender labels (HDTP §6.2 mandatory honesty). Typed so a surface picks a
// constant; there is no string parameter a caller could spoof through.
type Sender string

// The two sender labels (HDTP 6.2). Origin.Sender maps every surface to one of them.
const (
	// SenderAgent labels a message an agent composed or, for an inbound one, a peer that said so
	// or said nothing.
	SenderAgent Sender = "agent"
	// SenderHuman labels a message a person typed: the portal compose box, or a peer claiming so.
	SenderHuman Sender = "human"
)

// Origin is the surface a message was composed on, and it — not the caller — is
// what decides the sender label. The portal's compose box is the owner typing;
// every MCP surface is an agent acting on their behalf; an inbound message is
// the peer's own claim about their side, which only they can make.
//
// Each call site used to choose the label itself, so the rule lived as a
// convention repeated in five places, and any new surface (or an argument
// wired through by mistake) could label an agent's message as a person's. The
// label is now derived here, at the one point every message passes through.
type Origin string

const (
	// OriginPortal: the owner's own compose box. Anything that is not an MCP
	// surface is this — a human is at the keyboard.
	OriginPortal Origin = "portal"
	// OriginMCP: any MCP surface — the owner MCP, an agent harness.
	OriginMCP Origin = "mcp"
	// OriginPeer: inbound over the public surface. The sending node labels its
	// own side (§6.2); we validate the claim but cannot verify it, and an
	// absent label means agent.
	OriginPeer Origin = "peer"
	// OriginStored: re-sending a row this node already recorded — a retry. The label was decided when the message was
	// composed and is a fact on the row; re-deriving it from a surface would
	// answer for whichever surface happens to be running the sweep, which is
	// none of them. Recording under this origin is refused: a stored message
	// has already been recorded once.
	OriginStored Origin = "stored"
)

// Sender is the label this origin implies. Only OriginPeer carries a claim.
func (o Origin) Sender() Sender {
	if o == OriginPortal {
		return SenderHuman
	}
	return SenderAgent
}

// Label is the sender this message carries, decided by its origin. The stored
// row and the wire must use the same one, and neither may take it from a
// caller: only an inbound message has a label its sender alone can supply.
func (in Input) Label() Sender {
	if in.Origin == OriginPeer || in.Origin == OriginStored {
		return in.Sender
	}
	return in.Origin.Sender()
}

// Direction is whether a message came to this node or is going from it; it is stored as the
// message's direction and is part of the idempotency key, so a msg_id used inbound never swallows
// an outbound message.
type Direction string

const (
	// DirIn: a message a contact sent. It is recorded as delivered; its msg_id is not shared
	// with DirOut's in the idempotency key.
	DirIn Direction = "in"
	// DirOut: composed here for a contact. Recorded as pending until a peer accepts it.
	DirOut Direction = "out"
)

const maxTextBytes = 16 * 1024 // HDTP §12

// maxOwnerTopicBytes bounds the topic an owner starts a thread with at what a BatonDeck host accepts
// in `send_message`, so it reaches a hosted peer; a peer's reaches this node under MaxFieldBytes.
const maxOwnerTopicBytes = 256

// ConversationStore is what the service acts on: the message store, and one transaction for the
// writes that must land together (a message and its thread row; a deletion's rows).
type ConversationStore interface {
	store.MessageStore
	Atomically(ctx context.Context, fn func(tx store.Store) error) error
}

// Service records and deletes messages and threads in a ConversationStore. It writes rows only; it
// has no path to the wire, delivery of an outbound message is internal/node's. Bus, when set,
// receives an EventMessage for each message newly recorded. Blobs, when set, is where DeleteThread
// removes the files the deleted conversation alone referred to; nil leaves the files (tests).
type Service struct {
	Store ConversationStore
	Bus   *Bus // optional: events fan out when set (SPEC §7.6)
	Blobs BlobRemover
	Now   func() time.Time
	// OnError hears what the service did not finish and could not answer as a failure: the files of a
	// deleted conversation it could not collect. nil drops it (tests).
	OnError func(error)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Input is one message to record. MsgID is required and is the idempotency key together with the
// account, the contact and the direction.
type Input struct {
	MsgID    string
	ThreadID string // "" = start a new thread
	Topic    string // used only when the thread is created
	Text     string
	ReplyTo  string
	// Origin is the surface this came from; it decides Sender for everything
	// this node composes. Required.
	Origin Origin
	// Sender is meaningful only for OriginPeer, where it carries the peer's
	// claim about their own side. For anything this node composes it is
	// overwritten from Origin, so a caller cannot mislabel an agent as a person.
	Sender Sender
	// ExpiresAt is when outbound retries stop (SPEC §7.1, HDTP §7). 0 lets the
	// node apply the 24 h default.
	ExpiresAt int64
}

// Result is what Record answers: the thread the message is in, and the status of its row. Status is
// delivered for a message recorded inbound, pending for one recorded outbound, and the original
// row's current status when msg_id was already recorded (a replay writes nothing).
type Result struct {
	ThreadID string
	Status   string
}

// Record stores one message in the given direction with full idempotency: a
// replayed (account, contact, msg_id) returns the ORIGINAL result and writes
// nothing (HDTP §6.2).
func (s *Service) Record(ctx context.Context, accountID, contactFpr string, dir Direction, in Input) (Result, error) {
	return s.record(ctx, accountID, contactFpr, dir, in, "text")
}

func (s *Service) record(ctx context.Context, accountID, contactFpr string, dir Direction, in Input, kind string) (Result, error) {
	res, fresh, err := s.write(ctx, s.Store, accountID, contactFpr, dir, in, kind)
	if err == nil && fresh {
		s.publish(accountID, contactFpr, res.ThreadID)
	}
	return res, err
}

// publish tells the bus a message was recorded in a thread.
func (s *Service) publish(accountID, contactFpr, threadID string) {
	if s.Bus != nil {
		s.Bus.Publish(Event{Kind: EventMessage, AccountID: accountID, ThreadID: threadID, ContactFpr: contactFpr})
	}
}

// write is record's work against st, which is the service's store or a transaction a caller holds
// (MediaService stores a file and records its message in one). fresh says a message was written,
// which is when the caller publishes it.
func (s *Service) write(ctx context.Context, st ConversationStore, accountID, contactFpr string, dir Direction, in Input, kind string) (res Result, fresh bool, err error) {
	if in.MsgID == "" {
		return Result{}, false, fmt.Errorf("%w: msg_id required", ErrBadRequest)
	}
	switch in.Origin {
	case OriginPortal, OriginMCP:
		// The surface decides. A caller's claim is not consulted.
		in.Sender = in.Label()
	case OriginPeer:
		if in.Sender != SenderAgent && in.Sender != SenderHuman {
			return Result{}, false, fmt.Errorf("%w: sender must be agent|human", ErrBadRequest)
		}
	case OriginStored:
		// A stored message has been recorded once already; recording it again
		// would duplicate the row the retry is trying to deliver.
		return Result{}, false, fmt.Errorf("%w: a stored message cannot be recorded again", ErrBadRequest)
	default:
		return Result{}, false, fmt.Errorf("%w: origin required (portal|mcp|peer)", ErrBadRequest)
	}
	if len(in.Text) > maxTextBytes {
		return Result{}, false, fmt.Errorf("%w: text over 16 KiB", ErrTooLarge)
	}
	owner := in.Origin == OriginPortal || in.Origin == OriginMCP
	if owner && len(in.Topic) > maxOwnerTopicBytes {
		return Result{}, false, fmt.Errorf("%w: topic over 256 bytes", ErrTooLarge)
	}

	// Idempotency first: the same msg_id is acknowledged, never re-executed.
	if prev, err := st.GetMessageByMsgID(ctx, accountID, contactFpr, string(dir), in.MsgID); err == nil {
		return Result{ThreadID: prev.ThreadID, Status: prev.Status}, false, nil
	}

	nowTS := s.now().Unix()
	threadID := in.ThreadID
	if threadID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return Result{}, false, err
		}
		threadID = hex.EncodeToString(b)
	}
	// Shared-id semantics (HDTP §7): adopt the peer's thread id, creating the
	// thread locally on first sight — but never across contacts.
	th, err := st.GetThread(ctx, accountID, threadID)
	held := err == nil
	if held {
		if th.ContactFpr != contactFpr {
			return Result{}, false, fmt.Errorf("%w: thread belongs to another contact", ErrBadRequest)
		}
		if owner && in.Topic != "" {
			return Result{}, false, fmt.Errorf("%w: a topic is given when a thread is started, and that thread exists", ErrBadRequest)
		}
	}
	thread := store.Thread{
		ID: threadID, AccountID: accountID, ContactFpr: contactFpr,
		Topic: in.Topic, CreatedAt: nowTS, LastAt: nowTS,
	}

	// An INBOUND message has arrived — "delivered" is simply true of it. An
	// OUTBOUND one has not gone anywhere yet: this package writes rows and has
	// no path to the wire at all, so claiming delivery here told the owner their
	// message had been sent when nothing had left the machine. It becomes
	// `delivered` when a peer accepts it (SetMessageStatus, §7.1).
	status := "delivered"
	if dir == DirOut {
		status = "pending"
	}
	// The thread row and the message land together. A conversation deleted between the read above
	// and these writes leaves no thread to touch, and the message then starts it afresh: a message
	// is never written under a thread row that is gone, where no inbox and no export would find it.
	err = st.Atomically(ctx, func(tx store.Store) error {
		if held {
			touched, err := tx.TouchThread(ctx, accountID, threadID, nowTS)
			if err != nil {
				return err
			}
			held = touched > 0
		}
		if !held {
			if err := tx.InsertThread(ctx, thread); err != nil {
				return err
			}
		}
		return tx.InsertMessage(ctx, store.Message{
			AccountID: accountID, ContactFpr: contactFpr, MsgID: in.MsgID,
			ThreadID: threadID, Direction: string(dir), Sender: string(in.Sender),
			Kind: kind, Body: in.Text, ReplyTo: in.ReplyTo, Status: status, CreatedAt: nowTS,
			ExpiresAt: in.ExpiresAt,
		})
	})
	if err != nil {
		// Raced duplicate: someone recorded the same msg_id between our check and
		// insert — return the original, honoring idempotency under concurrency.
		if prev, lookupErr := st.GetMessageByMsgID(ctx, accountID, contactFpr, string(dir), in.MsgID); lookupErr == nil {
			return Result{ThreadID: prev.ThreadID, Status: prev.Status}, false, nil
		}
		return Result{}, false, err
	}
	return Result{ThreadID: threadID, Status: status}, true, nil
}

// Thread returns a thread's messages in order.
func (s *Service) Thread(ctx context.Context, accountID, threadID string) ([]store.Message, error) {
	return s.Store.ListMessagesByThread(ctx, accountID, threadID)
}
