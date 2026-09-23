// Package messaging implements threads and messages (SPEC §7, PACT §6.2/§7):
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

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

var (
	ErrTooLarge   = errors.New("too_large")
	ErrBadRequest = errors.New("bad_request")
)

// Sender labels (PACT §6.2 mandatory honesty). Typed so a surface picks a
// constant; there is no string parameter a caller could spoof through.
type Sender string

const (
	SenderAgent Sender = "agent"
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

type Direction string

const (
	DirIn  Direction = "in"
	DirOut Direction = "out"
)

const maxTextBytes = 16 * 1024 // PACT §12

type Service struct {
	Store store.Store
	Bus   *Bus // optional: events fan out when set (SPEC §7.6)
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

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
	// ExpiresAt is when outbound retries stop (SPEC §7.1, PACT §7). 0 lets the
	// node apply the 24 h default.
	ExpiresAt int64
}

type Result struct {
	ThreadID string
	Status   string // delivered | queued_for_human
}

// Record stores one message in the given direction with full idempotency: a
// replayed (account, contact, msg_id) returns the ORIGINAL result and writes
// nothing (PACT §6.2).
func (s *Service) Record(ctx context.Context, accountID, contactFpr string, dir Direction, in Input) (Result, error) {
	return s.record(ctx, accountID, contactFpr, dir, in, "text")
}

func (s *Service) record(ctx context.Context, accountID, contactFpr string, dir Direction, in Input, kind string) (Result, error) {
	if in.MsgID == "" {
		return Result{}, fmt.Errorf("%w: msg_id required", ErrBadRequest)
	}
	switch in.Origin {
	case OriginPortal, OriginMCP:
		// The surface decides. A caller's claim is not consulted.
		in.Sender = in.Label()
	case OriginPeer:
		if in.Sender != SenderAgent && in.Sender != SenderHuman {
			return Result{}, fmt.Errorf("%w: sender must be agent|human", ErrBadRequest)
		}
	case OriginStored:
		// A stored message has been recorded once already; recording it again
		// would duplicate the row the retry is trying to deliver.
		return Result{}, fmt.Errorf("%w: a stored message cannot be recorded again", ErrBadRequest)
	default:
		return Result{}, fmt.Errorf("%w: origin required (portal|mcp|peer)", ErrBadRequest)
	}
	if len(in.Text) > maxTextBytes {
		return Result{}, fmt.Errorf("%w: text over 16 KiB", ErrTooLarge)
	}

	// Idempotency first: the same msg_id is acknowledged, never re-executed.
	if prev, err := s.Store.GetMessageByMsgID(ctx, accountID, contactFpr, string(dir), in.MsgID); err == nil {
		return Result{ThreadID: prev.ThreadID, Status: prev.Status}, nil
	}

	nowTS := s.now().Unix()
	threadID := in.ThreadID
	if threadID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return Result{}, err
		}
		threadID = hex.EncodeToString(b)
	}
	// Shared-id semantics (PACT §7): adopt the peer's thread id, creating the
	// thread locally on first sight — but never across contacts.
	th, err := s.Store.GetThread(ctx, accountID, threadID)
	switch {
	case err == nil:
		if th.ContactFpr != contactFpr {
			return Result{}, fmt.Errorf("%w: thread belongs to another contact", ErrBadRequest)
		}
		if err := s.Store.TouchThread(ctx, accountID, threadID, nowTS); err != nil {
			return Result{}, err
		}
	default:
		if err := s.Store.InsertThread(ctx, store.Thread{
			ID: threadID, AccountID: accountID, ContactFpr: contactFpr,
			Topic: in.Topic, CreatedAt: nowTS, LastAt: nowTS,
		}); err != nil {
			return Result{}, err
		}
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
	err = s.Store.InsertMessage(ctx, store.Message{
		AccountID: accountID, ContactFpr: contactFpr, MsgID: in.MsgID,
		ThreadID: threadID, Direction: string(dir), Sender: string(in.Sender),
		Kind: kind, Body: in.Text, ReplyTo: in.ReplyTo, Status: status, CreatedAt: nowTS,
		ExpiresAt: in.ExpiresAt,
	})
	if err != nil {
		// Raced duplicate: someone recorded the same msg_id between our check and
		// insert — return the original, honoring idempotency under concurrency.
		if prev, lookupErr := s.Store.GetMessageByMsgID(ctx, accountID, contactFpr, string(dir), in.MsgID); lookupErr == nil {
			return Result{ThreadID: prev.ThreadID, Status: prev.Status}, nil
		}
		return Result{}, err
	}
	if s.Bus != nil {
		s.Bus.Publish(Event{Kind: EventMessage, AccountID: accountID, ThreadID: threadID, ContactFpr: contactFpr})
	}
	return Result{ThreadID: threadID, Status: status}, nil
}

// Thread returns a thread's messages in order.
func (s *Service) Thread(ctx context.Context, accountID, threadID string) ([]store.Message, error) {
	return s.Store.ListMessagesByThread(ctx, accountID, threadID)
}
