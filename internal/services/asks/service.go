// Package asks is what an owner's agent puts before its owner (docs/release/owner-asks-2026-10-19.md,
// N1): an ask, a question about one message of one thread that waits for the owner's answer, and a
// notice, which tells and waits for nothing. Each is an A2UI surface composed from the node's
// catalog (catalog.go). It is written once, below its doors: the owner MCP's tools (the agent asks,
// tells, withdraws and reads) and the portal (the owner reads and answers). Every answer becomes one
// plain line (AnswerLine), the line the agent reads back.
//
// A ready reply the owner chooses, or what they type in the ask's TextField, is sent to the contact
// as the owner's own message, labelled human, through the node's send (SPEC §7.1); any message the
// owner writes to that contact from the portal answers the contact's open ask too (OwnerSend). A
// date, a time or a button answers without sending anything. An ask is open for Lifetime and then
// expires; a notice stays. Neither leaves the node: HDTP's wire is untouched.
package asks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// Lifetime is how long an ask stays open before it expires.
const Lifetime = 24 * time.Hour

// ListLimit is the most asks and notices a list returns.
const ListLimit = 100

// The statuses an ask or a notice has: the bus's, which its events carry.
const (
	StatusOpen      = messaging.AskOpen
	StatusAnswered  = messaging.AskAnswered
	StatusExpired   = messaging.AskExpired
	StatusWithdrawn = messaging.AskWithdrawn
	StatusPosted    = messaging.AskPosted
)

// The audit actions the service writes, one row per change and per refusal, in the node's naming.
const (
	auditCreate   = "ask_create"
	auditAnswer   = "ask_answer"
	auditExpire   = "ask_expire"
	auditWithdraw = "ask_withdraw"
	auditNotice   = "notice_create"
)

// Send is the node's send of a text message (node.Node.SendMessage); SendMedia its send of a file.
type (
	Send      func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error)
	SendMedia func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error)
)

// Service holds the asks and notices of every account on the store.
type Service struct {
	store store.Store
	bus   *messaging.Bus
	// audit writes as the owner (the agent's tools and the owner's answers), system as the node (an
	// expiry).
	audit, system func(action, resource, outcome string)
	send          Send
	// Now is the clock; tests move it.
	Now func() time.Time
}

// New is the service over st, publishing on bus (nil publishes nothing), sending a chosen reply
// through send, auditing the owner's and the agent's actions through audit and an expiry through
// system.
func New(st store.Store, bus *messaging.Bus, send Send, audit, system func(action, resource, outcome string)) *Service {
	return &Service{store: st, bus: bus, send: send, audit: audit, system: system, Now: time.Now}
}

// View is an ask or a notice as every door shows it: its fields, listed, and never the row.
type View struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	ThreadID     string          `json:"thread_id"`
	Contact      string          `json:"contact"`
	ForMessageID string          `json:"for_message_id"`
	Status       string          `json:"status"`
	TLDR         string          `json:"tldr"`
	Surface      json.RawMessage `json:"surface"`
	AnswerText   string          `json:"answer_text"`
	CreatedAt    int64           `json:"created_at"`
	UpdatedAt    int64           `json:"updated_at"`
	// ExpiresAt is 0 for a notice.
	ExpiresAt int64 `json:"expires_at"`
}

// view is the row as shown at now: an open ask whose time has come reads as expired, whether or not
// the sweep has written it yet.
func (s *Service) view(a store.OwnerAsk, now int64) View {
	status := a.Status
	if status == StatusOpen && a.ExpiresAt <= now {
		status = StatusExpired
	}
	v := View{ID: a.ID, Kind: a.Kind, ThreadID: a.ThreadID, Contact: a.ContactFpr, ForMessageID: a.ForMsgID,
		Status: status, Surface: json.RawMessage(a.Surface), AnswerText: a.AnswerText,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, ExpiresAt: a.ExpiresAt}
	if sf, err := Parse([]byte(a.Surface), a.Kind); err == nil {
		v.TLDR = sf.TLDR()
	}
	return v
}

func (s *Service) now() time.Time { return s.Now() }

func newID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand failure is unrecoverable
	}
	return prefix + hex.EncodeToString(b)
}

func (s *Service) publish(a store.OwnerAsk, status string) {
	if s.bus != nil {
		s.bus.Publish(messaging.Event{Kind: messaging.EventAsk, AccountID: a.AccountID, ThreadID: a.ThreadID,
			ContactFpr: a.ContactFpr, Ref: a.ID, Status: status})
	}
}

func resource(accountID string, rest ...string) string {
	return strings.Join(append([]string{"account:" + accountID}, rest...), " ")
}

// refused audits a refusal by its code and hands it back.
func (s *Service) refused(action, res string, err error) error {
	code, _ := refusal.Of(err)
	s.audit(action, res, code)
	return err
}

// Ask puts an ask before the owner: surface, about message forMsgID of thread threadID. Asking again
// about the same message answers the ask the first call made; another open ask on the thread is a
// conflict until it is answered, withdrawn or expires.
func (s *Service) Ask(ctx context.Context, accountID, threadID, forMsgID string, surface []byte) (View, error) {
	return s.put(ctx, KindAsk, accountID, threadID, forMsgID, surface)
}

// Notify puts a notice before the owner: it tells, and nothing in it answers.
func (s *Service) Notify(ctx context.Context, accountID, threadID, forMsgID string, surface []byte) (View, error) {
	return s.put(ctx, KindNotice, accountID, threadID, forMsgID, surface)
}

func (s *Service) put(ctx context.Context, kind, accountID, threadID, forMsgID string, surface []byte) (View, error) {
	action := auditCreate
	if kind == KindNotice {
		action = auditNotice
	}
	res := resource(accountID, "thread:"+threadID, "msg:"+forMsgID)
	if threadID == "" || forMsgID == "" {
		return View{}, s.refused(action, res, refusal.BadRequest("thread_id and for_message_id are required", nil))
	}
	sf, err := Parse(surface, kind)
	if err != nil {
		var inv Invalid
		if errors.As(err, &inv) && inv.TooLarge {
			return View{}, s.refused(action, res, refusal.TooLarge(inv.Error(), nil))
		}
		return View{}, s.refused(action, res, refusal.BadRequest(err.Error(), nil))
	}
	th, err := s.store.GetThread(ctx, accountID, threadID)
	if errors.Is(err, store.ErrNotFound) {
		return View{}, s.refused(action, res, refusal.NotFound("no thread by that id on this account", nil))
	}
	if err != nil {
		return View{}, err
	}
	if !s.inThread(ctx, accountID, th, forMsgID) {
		return View{}, s.refused(action, res, refusal.NotFound("no message by that id in this thread", nil))
	}
	if kind == KindAsk {
		c, err := s.store.GetContact(ctx, accountID, th.ContactFpr)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return View{}, err
		}
		if err != nil || c.Status != "active" {
			return View{}, s.refused(action, res, refusal.Conflict("the contact of this thread is not active: a reply the owner chose could not be sent", nil))
		}
	}
	now := s.now()
	// A thread's ask whose time has come is closed first, so it does not hold the thread.
	if prev, err := s.store.GetOpenOwnerAsk(ctx, accountID, threadID); err == nil && prev.ExpiresAt <= now.Unix() {
		s.expire(ctx, prev, now)
	}
	stored, err := json.Marshal(storedSurface(sf))
	if err != nil {
		return View{}, err
	}
	a := store.OwnerAsk{ID: newID(kind + "_"), AccountID: accountID, Kind: kind, ThreadID: threadID, ContactFpr: th.ContactFpr,
		ForMsgID: forMsgID, Surface: string(stored), Status: StatusOpen, CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
		ExpiresAt: now.Add(Lifetime).Unix()}
	if kind == KindNotice {
		a.Status, a.ExpiresAt = StatusPosted, 0
	}
	ok, err := s.store.InsertOwnerAsk(ctx, a)
	if err != nil {
		return View{}, err
	}
	if !ok {
		// The same call again finds what it made; anything else is the thread's open ask.
		if prev, err := s.store.GetOwnerAskFor(ctx, accountID, kind, threadID, forMsgID); err == nil {
			return s.view(prev, now.Unix()), nil
		}
		open, err := s.store.GetOpenOwnerAsk(ctx, accountID, threadID)
		if err != nil {
			return View{}, err
		}
		return View{}, s.refused(action, res, refusal.Conflict("this thread already has an open ask ("+open.ID+"): withdraw it, or wait for the owner's answer", nil))
	}
	s.audit(action, resource(accountID, a.Kind+":"+a.ID, "thread:"+threadID, "msg:"+forMsgID), "ok")
	s.publish(a, a.Status)
	return s.view(a, now.Unix()), nil
}

// inThread says whether the thread holds a message with msgID, either way.
func (s *Service) inThread(ctx context.Context, accountID string, th store.Thread, msgID string) bool {
	for _, dir := range []messaging.Direction{messaging.DirIn, messaging.DirOut} {
		if m, err := s.store.GetMessageByMsgID(ctx, accountID, th.ContactFpr, string(dir), msgID); err == nil && m.ThreadID == th.ID {
			return true
		}
	}
	return false
}

// storedSurface is the surface as the node keeps it: the two messages, root first, rebuilt from
// what Parse read, so nothing Parse did not read is kept.
func storedSurface(sf Surface) []any {
	return []any{
		map[string]any{"version": Version, "createSurface": map[string]any{"surfaceId": sf.ID, "catalogId": CatalogID}},
		map[string]any{"version": Version, "updateComponents": map[string]any{"surfaceId": sf.ID, "components": sf.Components}},
	}
}

// Get returns one of the account's asks or notices.
func (s *Service) Get(ctx context.Context, accountID, id string) (View, error) {
	a, err := s.store.GetOwnerAsk(ctx, accountID, id)
	if errors.Is(err, store.ErrNotFound) {
		return View{}, refusal.NotFound("no ask or notice by that id on this account", nil)
	}
	if err != nil {
		return View{}, err
	}
	now := s.now()
	if a.Status == StatusOpen && a.ExpiresAt <= now.Unix() {
		a = s.expire(ctx, a, now)
	}
	return s.view(a, now.Unix()), nil
}

// Filter narrows List: Open to open asks alone, Contact to the threads with one contact (oldest
// first); with neither, the account's asks and notices, newest first.
type Filter struct {
	Open    bool
	Contact string
}

// List returns up to ListLimit of the account's asks and notices.
func (s *Service) List(ctx context.Context, accountID string, f Filter) ([]View, error) {
	if _, err := s.store.GetAccountByID(ctx, accountID); errors.Is(err, store.ErrNotFound) {
		return nil, refusal.NotFound("no account by that id on this node", nil)
	} else if err != nil {
		return nil, err
	}
	var rows []store.OwnerAsk
	var err error
	switch {
	case f.Contact != "":
		rows, err = s.store.ListContactOwnerAsks(ctx, accountID, f.Contact, ListLimit)
	case f.Open:
		rows, err = s.store.ListOpenOwnerAsks(ctx, accountID, ListLimit)
	default:
		rows, err = s.store.ListOwnerAsks(ctx, accountID, ListLimit)
	}
	if err != nil {
		return nil, err
	}
	now := s.now().Unix()
	out := make([]View, 0, len(rows))
	for _, a := range rows {
		v := s.view(a, now)
		if f.Open && v.Status != StatusOpen {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// CountOpen counts the account's open asks: the portal's badge.
func (s *Service) CountOpen(ctx context.Context, accountID string) (int64, error) {
	return s.store.CountOpenOwnerAsks(ctx, accountID, s.now().Unix())
}

// Withdraw closes an open ask the agent no longer needs answered.
func (s *Service) Withdraw(ctx context.Context, accountID, id string) (View, error) {
	res := resource(accountID, "ask:"+id)
	a, err := s.open(ctx, accountID, id)
	if err != nil {
		return View{}, s.refused(auditWithdraw, res, err)
	}
	now := s.now()
	ok, err := s.store.CloseOwnerAsk(ctx, accountID, id, StatusWithdrawn, "", now.Unix())
	if err != nil {
		return View{}, err
	}
	if !ok {
		return View{}, s.refused(auditWithdraw, res, refusal.Conflict("this ask was closed meanwhile", nil))
	}
	s.audit(auditWithdraw, res, "ok")
	s.publish(a, StatusWithdrawn)
	a.Status, a.UpdatedAt = StatusWithdrawn, now.Unix()
	return s.view(a, now.Unix()), nil
}

// open returns the ask id if it is open: not_found for none, conflict for a notice or an ask
// already closed. One whose time has come is expired now, and is a conflict.
func (s *Service) open(ctx context.Context, accountID, id string) (store.OwnerAsk, error) {
	a, err := s.store.GetOwnerAsk(ctx, accountID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.OwnerAsk{}, refusal.NotFound("no ask by that id on this account", nil)
	}
	if err != nil {
		return store.OwnerAsk{}, err
	}
	if a.Kind != KindAsk {
		return store.OwnerAsk{}, refusal.Conflict("that is a notice: nothing answers it", nil)
	}
	now := s.now()
	if a.Status == StatusOpen && a.ExpiresAt <= now.Unix() {
		a = s.expire(ctx, a, now)
	}
	if a.Status != StatusOpen {
		return store.OwnerAsk{}, refusal.Conflict("this ask is "+a.Status, nil)
	}
	return a, nil
}

// Answer is what the owner did on an open ask: Component is the id of the component they acted on,
// Value what it holds (a ready reply's label, the text typed, the date or time picked as ISO 8601;
// nothing for a Button).
type Answer struct {
	Component string
	Value     string
}

// Answer answers an open ask. A ready reply or typed text is sent to the contact first, as the
// owner's message, under the ask's id as its msg_id, so answering twice sends once.
func (s *Service) Answer(ctx context.Context, accountID, id string, ans Answer) (View, error) {
	res := resource(accountID, "ask:"+id)
	a, err := s.open(ctx, accountID, id)
	if err != nil {
		return View{}, s.refused(auditAnswer, res, err)
	}
	sf, err := Parse([]byte(a.Surface), KindAsk)
	if err != nil {
		return View{}, err
	}
	c, ok := sf.Find(ans.Component)
	if spec, _ := componentNamed(c.Name); !ok || !spec.interactive {
		return View{}, s.refused(auditAnswer, res, refusal.BadRequest("no component by that id answers this ask", nil))
	}
	who, err := s.ownerName(ctx, accountID)
	if err != nil {
		return View{}, err
	}
	var line, send string
	switch c.Name {
	case "Choice":
		chosen := ""
		for _, o := range c.Options {
			if o.Label == ans.Value {
				chosen = o.Label
			}
		}
		if chosen == "" {
			return View{}, s.refused(auditAnswer, res, refusal.BadRequest("that is not one of the ready replies", nil))
		}
		line, send = AnswerLine(who, "chose", chosen), chosen
	case "TextField":
		text := strings.TrimSpace(ans.Value)
		if text == "" {
			return View{}, s.refused(auditAnswer, res, refusal.BadRequest("nothing was written", nil))
		}
		line, send = AnswerLine(who, "wrote", text), text
	case "DateTimeInput":
		when, err := picked(c, ans.Value)
		if err != nil {
			return View{}, s.refused(auditAnswer, res, err)
		}
		line = who + " picked: " + when
	case "Button":
		label, _ := sf.Find(c.Child)
		line = AnswerLine(who, "pressed", label.Text)
	}
	if send != "" {
		_, err := s.send(ctx, accountID, a.ContactFpr, messaging.Input{MsgID: a.ID, ThreadID: a.ThreadID, Text: send,
			Origin: messaging.OriginPortal})
		// Recorded and not yet delivered is a message the node keeps trying: the owner answered.
		if _, recorded := refusal.Why(err); err != nil && !recorded {
			return View{}, s.refused(auditAnswer, res, err)
		}
	}
	return s.close(ctx, a, line, res)
}

// close records the answer line on an open ask, once.
func (s *Service) close(ctx context.Context, a store.OwnerAsk, line, res string) (View, error) {
	now := s.now()
	ok, err := s.store.CloseOwnerAsk(ctx, a.AccountID, a.ID, StatusAnswered, line, now.Unix())
	if err != nil {
		return View{}, err
	}
	if !ok {
		return View{}, s.refused(auditAnswer, res, refusal.Conflict("this ask was closed meanwhile", nil))
	}
	s.audit(auditAnswer, res, "ok")
	s.publish(a, StatusAnswered)
	a.Status, a.AnswerText, a.UpdatedAt = StatusAnswered, line, now.Unix()
	return s.view(a, now.Unix()), nil
}

// OwnerSend is send for a message the owner writes from the portal: when the contact has an open
// ask, the message goes to that ask's thread and answers it ("Ana wrote: …").
func (s *Service) OwnerSend(send Send) Send {
	return func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
		a, ok := s.contactAsk(ctx, accountID, contactFpr)
		if ok {
			in.ThreadID = a.ThreadID
		}
		r, err := send(ctx, accountID, contactFpr, in)
		if ok {
			s.answeredBySending(ctx, a, err, "wrote", in.Text)
		}
		return r, err
	}
}

// OwnerSendMedia is OwnerSend for a file ("Ana sent a file: …").
func (s *Service) OwnerSendMedia(send SendMedia) SendMedia {
	return func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error) {
		a, ok := s.contactAsk(ctx, accountID, contactFpr)
		if ok {
			in.ThreadID = a.ThreadID
		}
		r, err := send(ctx, accountID, contactFpr, in, filename, mime, data)
		if ok {
			s.answeredBySending(ctx, a, err, "sent a file", filename)
		}
		return r, err
	}
}

// contactAsk is the contact's newest open ask, if it has one still in time.
func (s *Service) contactAsk(ctx context.Context, accountID, contactFpr string) (store.OwnerAsk, bool) {
	a, err := s.store.GetContactOpenOwnerAsk(ctx, accountID, contactFpr)
	if err != nil || a.ExpiresAt <= s.now().Unix() {
		return store.OwnerAsk{}, false
	}
	return a, true
}

// answeredBySending closes a with the line for what the owner sent, if it was recorded.
func (s *Service) answeredBySending(ctx context.Context, a store.OwnerAsk, err error, verb, what string) {
	if _, recorded := refusal.Why(err); err != nil && !recorded {
		return
	}
	who, nerr := s.ownerName(ctx, a.AccountID)
	if nerr != nil {
		return
	}
	// A failure here leaves the ask open, as the owner can see; the message went.
	_, _ = s.close(ctx, a, AnswerLine(who, verb, what), resource(a.AccountID, "ask:"+a.ID))
}

// ownerName is who the answer line names: the account's display name.
func (s *Service) ownerName(ctx context.Context, accountID string) (string, error) {
	acct, err := s.store.GetAccountByID(ctx, accountID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(acct.DisplayName) == "" {
		return "The owner", nil
	}
	return acct.DisplayName, nil
}

// AnswerLine is the one plain line an answer becomes, the line the agent reads: who, what they did,
// and what, quoted on one line (`Ana chose: "Confirm Wed 15:00"`).
func AnswerLine(who, verb, what string) string {
	return who + " " + verb + ": " + strconv.Quote(what)
}

// picked reads a DateTimeInput's value as the browser gave it, within the input's bounds, and words
// it for the answer line: "Thu 22 Oct 2026 14:00 +01:00", "Thu 22 Oct 2026" or "14:00".
func picked(c Component, v string) (string, error) {
	bad := refusal.BadRequest("that is not a date or time this input takes", nil)
	switch {
	case c.EnableDate && c.EnableTime:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "", bad
		}
		if !within(c, t, time.RFC3339) {
			return "", refusal.BadRequest("that is outside the times this input allows", nil)
		}
		return t.Format("Mon 2 Jan 2006 15:04 -07:00"), nil
	case c.EnableDate:
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return "", bad
		}
		if !within(c, t, "2006-01-02") {
			return "", refusal.BadRequest("that is outside the dates this input allows", nil)
		}
		return t.Format("Mon 2 Jan 2006"), nil
	default:
		t, err := time.Parse("15:04", v)
		if err != nil {
			return "", bad
		}
		if !within(c, t, "15:04") {
			return "", refusal.BadRequest("that is outside the times this input allows", nil)
		}
		return t.Format("15:04"), nil
	}
}

// within says t is inside the input's min and max, each read in layout; a bound that does not read
// so bounds nothing.
func within(c Component, t time.Time, layout string) bool {
	if lo, err := time.Parse(layout, c.Min); err == nil && t.Before(lo) {
		return false
	}
	if hi, err := time.Parse(layout, c.Max); err == nil && t.After(hi) {
		return false
	}
	return true
}

// expire closes an open ask whose time has come, once, and hands back the row as it now is.
func (s *Service) expire(ctx context.Context, a store.OwnerAsk, now time.Time) store.OwnerAsk {
	ok, err := s.store.ExpireOwnerAsk(ctx, a.AccountID, a.ID, now.Unix())
	if err != nil || !ok {
		if fresh, err := s.store.GetOwnerAsk(ctx, a.AccountID, a.ID); err == nil {
			return fresh
		}
		return a
	}
	s.system(auditExpire, resource(a.AccountID, "ask:"+a.ID, "thread:"+a.ThreadID), "ok")
	s.publish(a, StatusExpired)
	a.Status, a.UpdatedAt = StatusExpired, now.Unix()
	return a
}

// sweepBatch is the most asks one pass of the sweep expires.
const sweepBatch = 200

// ExpireDue expires every open ask whose time has come, of every account, and returns how many.
func (s *Service) ExpireDue(ctx context.Context) (int, error) {
	n := 0
	for {
		now := s.now()
		due, err := s.store.ListDueOwnerAsks(ctx, now.Unix(), sweepBatch)
		if err != nil {
			return n, err
		}
		for _, a := range due {
			if s.expire(ctx, a, now).Status == StatusExpired {
				n++
			}
		}
		if len(due) < sweepBatch {
			return n, nil
		}
	}
}

// LeaseName is the lease a process holds to run the expiry sweep (SPEC §11.1). An expiry is a
// conditional write, so a second process sweeping would expire nothing twice; the lease spares it the
// reads.
const LeaseName = "asks"

// SweepEvery is how often Run looks for asks whose time has come.
const SweepEvery = time.Minute

// Run expires due asks every SweepEvery until ctx ends, while leading says this process holds the
// sweep's lease.
func (s *Service) Run(ctx context.Context, leading func(context.Context) bool, onError func(error)) {
	t := time.NewTicker(SweepEvery)
	defer t.Stop()
	for {
		if leading == nil || leading(ctx) {
			if _, err := s.ExpireDue(ctx); err != nil && ctx.Err() == nil && onError != nil {
				onError(fmt.Errorf("asks: the expiry sweep: %w", err))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
