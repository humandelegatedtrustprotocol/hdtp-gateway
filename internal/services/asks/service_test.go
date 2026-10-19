package asks

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

const bob = "sha256:bob"

// rig is a real store, a real messaging service recording into it, and the service under test.
// The send records the message as the node's does, through messaging, and does not deliver: what
// reaches the contact's node is the portal observation's to show (scratchpad/feat-owner-asks).
type rig struct {
	t       *testing.T
	st      store.Store
	msg     *messaging.Service
	svc     *Service
	account string
	thread  string
	clock   time.Time
	sent    []messaging.Input
	audit   []string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "asks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "ana", DisplayName: "Ana", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: bob, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, st: st, account: a.ID, clock: time.Unix(1760000000, 0)}
	bus := messaging.NewBus(st)
	r.msg = &messaging.Service{Store: st, Bus: bus, Now: func() time.Time { return r.clock }}
	in, err := r.msg.Record(ctx, a.ID, bob, messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m1", Text: "Wed 15:00?"})
	if err != nil {
		t.Fatal(err)
	}
	r.thread = in.ThreadID
	send := func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
		r.sent = append(r.sent, in)
		return r.msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
	}
	rec := func(who string) func(action, resource, outcome string) {
		return func(action, resource, outcome string) { r.audit = append(r.audit, who+" "+action+" "+outcome) }
	}
	r.svc = New(st, bus, send, rec("owner"), rec("system"))
	r.svc.Now = func() time.Time { return r.clock }
	return r
}

func (r *rig) ask(surface string) View {
	r.t.Helper()
	v, err := r.svc.Ask(context.Background(), r.account, r.thread, "m1", []byte(surface))
	if err != nil {
		r.t.Fatalf("ask: %v", err)
	}
	return v
}

// act is the A2UI action the portal sends when the owner presses button, its event name, with
// context resolved from the card's data model.
func act(name, button, context string) []byte {
	return []byte(`{"version":"v0.9.1","action":{"name":"` + name + `","surfaceId":"s1","sourceComponentId":"` + button +
		`","timestamp":"2026-10-19T10:00:00Z","context":` + context + `}}`)
}

// chooseConfirm is the owner picking the first ready reply of the story's ask and pressing Send.
var chooseConfirm = act("answer", "send", `{"reply":["confirm"],"own":""}`)

func codeOf(err error) string {
	code, _ := refusal.Of(err)
	return code
}

// The ask the story needs: put, read, answered by a ready reply that goes to the contact as the
// owner's message on the ask's thread, and its line read back. One audit row per change.
func TestAChosenReadyReplyIsSentAsTheOwnersMessageAndAnswersTheAsk(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	if v.Status != StatusOpen || v.Kind != KindAsk || v.TLDR != "Bob proposes Wed 15:00 for 30 min." || v.Contact != bob ||
		v.ExpiresAt != r.clock.Add(Lifetime).Unix() {
		t.Fatalf("the ask: %+v", v)
	}
	got, err := r.svc.Answer(ctx, r.account, v.ID, chooseConfirm)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusAnswered || got.AnswerText != `Ana chose: "Confirm Wed 15:00"` {
		t.Fatalf("after the answer: %+v", got)
	}
	if len(r.sent) != 1 || r.sent[0].Text != "Confirm Wed 15:00" || r.sent[0].ThreadID != r.thread ||
		r.sent[0].Origin != messaging.OriginPortal || r.sent[0].MsgID != v.ID {
		t.Fatalf("sent: %+v", r.sent)
	}
	msgs, _ := r.st.ListMessagesByThread(ctx, r.account, r.thread)
	if last := msgs[len(msgs)-1]; last.Sender != "human" || last.Body != "Confirm Wed 15:00" || last.Direction != "out" {
		t.Fatalf("the message recorded: %+v", last)
	}
	read, err := r.svc.Get(ctx, r.account, v.ID)
	if err != nil || read.AnswerText != `Ana chose: "Confirm Wed 15:00"` || read.Status != StatusAnswered {
		t.Fatalf("Get: %+v %v", read, err)
	}
	// Answering again is refused, and sends nothing.
	if _, err := r.svc.Answer(ctx, r.account, v.ID, chooseConfirm); codeOf(err) != "conflict" {
		t.Fatalf("a second answer: %v", err)
	}
	if len(r.sent) != 1 {
		t.Fatalf("a second answer sent: %+v", r.sent)
	}
	if want := "owner ask_create ok,owner ask_answer ok,owner ask_answer conflict"; strings.Join(r.audit, ",") != want {
		t.Fatalf("audit %v, want %s", r.audit, want)
	}
	// The change log: the ask opened, then answered, each naming it.
	rows, _ := r.st.ChangesAfter(ctx, 0, 100)
	var asks []string
	for _, c := range rows {
		if e := messaging.EventOf(c); e.Kind == messaging.EventAsk {
			if e.Ref != v.ID || e.ThreadID != r.thread || e.ContactFpr != bob {
				t.Fatalf("an ask event: %+v", e)
			}
			asks = append(asks, e.Status)
		}
	}
	if strings.Join(asks, ",") != "open,answered" {
		t.Fatalf("ask events %v", asks)
	}
}

// The answer line is made in one place from the pressed Button and the values its context read:
// what the owner typed first (sent), then the ready reply they chose (sent), then a date or time
// (not sent); a Button that reads nothing is its label (not sent).
func TestEveryKindOfAnswerBecomesOneLine(t *testing.T) {
	cases := []struct {
		name, surface string
		ans           []byte
		line          string
		sends         string
	}{
		{"chosen", validAsks["the story's ask"], chooseConfirm, `Ana chose: "Confirm Wed 15:00"`, "Confirm Wed 15:00"},
		{"typed", validAsks["the story's ask"], act("answer", "send", `{"reply":[],"own":"  Thu 10:00 works better  "}`), `Ana wrote: "Thu 10:00 works better"`, "Thu 10:00 works better"},
		{"typed over chosen", validAsks["the story's ask"], act("answer", "send", `{"reply":["thu"],"own":"Thu, but 11:00"}`), `Ana wrote: "Thu, but 11:00"`, "Thu, but 11:00"},
		{"chosen, nothing typed", validAsks["the story's ask"], act("answer", "send", `{"reply":["thu"],"own":"   "}`), `Ana chose: "Ask for Thu instead"`, "Ask for Thu instead"},
		{"a date and time", validAsks["a date it sends"], act("answer", "send", `{"when":"2026-10-22T14:00:00+01:00"}`), "Ana picked: Thu 22 Oct 2026 14:00 +01:00", ""},
		{"a button", validAsks["a date and a button"], act("approve", "ok", `{"slot":"wed-15","n":1,"firm":true}`), `Ana pressed: "Approve"`, ""},
		{"a button with no context", validAsks["a button with no context"], act("seen", "ok", `{}`), `Ana pressed: "Approve"`, ""},
		{"a line break stays one line", validAsks["a TextField alone"], act("answer", "send", `{"own":"yes\nbut later"}`), `Ana wrote: "yes\nbut later"`, "yes\nbut later"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			v := r.ask(c.surface)
			got, err := r.svc.Answer(context.Background(), r.account, v.ID, c.ans)
			if err != nil {
				t.Fatal(err)
			}
			if got.AnswerText != c.line {
				t.Fatalf("line %q, want %q", got.AnswerText, c.line)
			}
			if c.sends == "" && len(r.sent) != 0 || c.sends != "" && (len(r.sent) != 1 || r.sent[0].Text != c.sends) {
				t.Fatalf("sent %+v, want %q", r.sent, c.sends)
			}
		})
	}
}

// Every refusal is coded, audited, and changes nothing: rule 3's set for each mutation.
func TestEveryRefusalIsCoded(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	other, _ := r.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "zed", DisplayName: "Zed", Algo: "p256"})
	good := []byte(validAsks["the story's ask"])
	for name, c := range map[string]struct {
		call func() error
		code string
	}{
		"an unknown thread": {func() error {
			_, err := r.svc.Ask(ctx, r.account, "0123456789abcdef0123456789abcdef", "m1", good)
			return err
		}, "not_found"},
		"a message not in the thread": {func() error { _, err := r.svc.Ask(ctx, r.account, r.thread, "m-none", good); return err }, "not_found"},
		"another account's thread":    {func() error { _, err := r.svc.Ask(ctx, other.ID, r.thread, "m1", good); return err }, "not_found"},
		"a malformed surface":         {func() error { _, err := r.svc.Ask(ctx, r.account, r.thread, "m1", []byte(`{"x":1}`)); return err }, "bad_request"},
		"an unknown component": {func() error {
			_, err := r.svc.Ask(ctx, r.account, r.thread, "m1", []byte(invalidSurfaces["an unknown component"].surface))
			return err
		}, "bad_request"},
		"an oversize surface": {func() error {
			_, err := r.svc.Ask(ctx, r.account, r.thread, "m1", []byte(invalidSurfaces["an oversize payload"].surface))
			return err
		}, "too_large"},
		"a ChoicePicker in a notice": {func() error {
			_, err := r.svc.Notify(ctx, r.account, r.thread, "m1", good)
			return err
		}, "bad_request"},
		"no ids":            {func() error { _, err := r.svc.Ask(ctx, r.account, "", "", good); return err }, "bad_request"},
		"an unknown ask":    {func() error { _, err := r.svc.Get(ctx, r.account, "ask_none"); return err }, "not_found"},
		"answer none":       {func() error { _, err := r.svc.Answer(ctx, r.account, "ask_none", chooseConfirm); return err }, "not_found"},
		"withdraw none":     {func() error { _, err := r.svc.Withdraw(ctx, r.account, "ask_none"); return err }, "not_found"},
		"list another node": {func() error { _, err := r.svc.List(ctx, "acct_none", Filter{}); return err }, "not_found"},
	} {
		if err := c.call(); codeOf(err) != c.code {
			t.Errorf("%s: %v (%s), want %s", name, err, codeOf(err), c.code)
		}
	}
	if l, _ := r.svc.List(ctx, r.account, Filter{}); len(l) != 0 {
		t.Fatalf("a refusal wrote an ask: %+v", l)
	}

	v := r.ask(string(good))
	for name, c := range map[string]struct {
		ans  []byte
		code string
	}{
		"not JSON":                      {[]byte("pick=confirm"), "bad_request"},
		"a reply not offered":           {act("answer", "send", `{"reply":["maybe"],"own":""}`), "bad_request"},
		"two replies":                   {act("answer", "send", `{"reply":["confirm","thu"],"own":""}`), "bad_request"},
		"a text of a number":            {act("answer", "send", `{"reply":[],"own":3}`), "bad_request"},
		"a component that is not there": {act("answer", "nope", `{}`), "bad_request"},
		"a component that answers not":  {act("answer", "pick", `{}`), "bad_request"},
		"another event":                 {act("other", "send", `{"reply":["confirm"],"own":""}`), "bad_request"},
		"a key the Button lacks":        {act("answer", "send", `{"reply":["confirm"],"own":"","extra":1}`), "bad_request"},
		"a key the Button has, missing": {act("answer", "send", `{"reply":["confirm"]}`), "bad_request"},
		"another surface":               {[]byte(strings.Replace(string(chooseConfirm), `"s1"`, `"s2"`, 1)), "bad_request"},
		"another version":               {[]byte(strings.Replace(string(chooseConfirm), `"v0.9.1"`, `"v0.9"`, 1)), "bad_request"},
		"nothing chosen or typed":       {act("answer", "send", `{"reply":[],"own":"   "}`), "bad_request"},
	} {
		if _, err := r.svc.Answer(ctx, r.account, v.ID, c.ans); codeOf(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	if _, err := r.svc.Get(ctx, other.ID, v.ID); codeOf(err) != "not_found" {
		t.Fatalf("another account's Get: %v", err)
	}
	if _, err := r.svc.Answer(ctx, other.ID, v.ID, chooseConfirm); codeOf(err) != "not_found" {
		t.Fatalf("another account's answer: %v", err)
	}
	if _, err := r.svc.Withdraw(ctx, other.ID, v.ID); codeOf(err) != "not_found" {
		t.Fatalf("another account's withdraw: %v", err)
	}
	if len(r.sent) != 0 {
		t.Fatalf("a refused answer sent: %+v", r.sent)
	}
	// The control: the owner's own answer goes through.
	if _, err := r.svc.Answer(ctx, r.account, v.ID, chooseConfirm); err != nil {
		t.Fatalf("the owner's answer: %v", err)
	}
}

// Asking twice about one message is one ask; another while it is open is a conflict; a withdrawn
// ask frees the thread and refuses an answer.
func TestOneOpenAskPerThreadAndWithdrawFreesIt(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	first := r.ask(validAsks["the story's ask"])
	again := r.ask(validAsks["a TextField alone"])
	if again.ID != first.ID {
		t.Fatalf("a retry about one message made %s, want %s", again.ID, first.ID)
	}
	if _, err := r.msg.Record(ctx, r.account, bob, messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m2", ThreadID: r.thread, Text: "or Thu?"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Ask(ctx, r.account, r.thread, "m2", []byte(validAsks["the story's ask"])); codeOf(err) != "conflict" {
		t.Fatalf("a second open ask: %v", err)
	}
	w, err := r.svc.Withdraw(ctx, r.account, first.ID)
	if err != nil || w.Status != StatusWithdrawn {
		t.Fatalf("withdraw: %+v %v", w, err)
	}
	if _, err := r.svc.Answer(ctx, r.account, first.ID, chooseConfirm); codeOf(err) != "conflict" {
		t.Fatalf("an answer to a withdrawn ask: %v", err)
	}
	if _, err := r.svc.Withdraw(ctx, r.account, first.ID); codeOf(err) != "conflict" {
		t.Fatalf("a second withdraw: %v", err)
	}
	if len(r.sent) != 0 {
		t.Fatalf("a withdrawn ask's answer sent: %+v", r.sent)
	}
	if _, err := r.svc.Ask(ctx, r.account, r.thread, "m2", []byte(validAsks["the story's ask"])); err != nil {
		t.Fatalf("the next ask after the withdraw: %v", err)
	}
}

// An ask expires after Lifetime on the clock: read as expired at once, written so once (one audit
// row, one event) by whichever comes first, the sweep or a read; an answer to it is refused.
func TestAnAskExpiresOnTheClock(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	r.clock = r.clock.Add(Lifetime - time.Second)
	if got, _ := r.svc.Get(ctx, r.account, v.ID); got.Status != StatusOpen {
		t.Fatalf("a second before its expiry: %s", got.Status)
	}
	if n, _ := r.svc.CountOpen(ctx, r.account); n != 1 {
		t.Fatalf("open count %d", n)
	}
	r.clock = r.clock.Add(time.Second)
	if l, _ := r.svc.List(ctx, r.account, Filter{}); len(l) != 1 || l[0].Status != StatusExpired {
		t.Fatalf("listed at its expiry: %+v", l)
	}
	if l, _ := r.svc.List(ctx, r.account, Filter{Open: true}); len(l) != 0 {
		t.Fatalf("an expired ask listed open: %+v", l)
	}
	if n, _ := r.svc.CountOpen(ctx, r.account); n != 0 {
		t.Fatalf("an expired ask counted open: %d", n)
	}
	n, err := r.svc.ExpireDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("the sweep expired %d (%v)", n, err)
	}
	if n, _ := r.svc.ExpireDue(ctx); n != 0 {
		t.Fatalf("a second sweep expired %d", n)
	}
	if _, err := r.svc.Answer(ctx, r.account, v.ID, chooseConfirm); codeOf(err) != "conflict" {
		t.Fatalf("an answer after expiry: %v", err)
	}
	if len(r.sent) != 0 {
		t.Fatalf("an expired ask's answer sent: %+v", r.sent)
	}
	expiries := 0
	for _, a := range r.audit {
		if a == "system ask_expire ok" {
			expiries++
		}
	}
	if expiries != 1 {
		t.Fatalf("audit %v: want one ask_expire", r.audit)
	}
	// An expired ask frees its thread for the next.
	if _, err := r.svc.Ask(ctx, r.account, r.thread, "m1", []byte(validAsks["the story's ask"])); err != nil {
		// The same message: the expired row is the one found, and that is what a retry gets.
		t.Fatalf("asking again about the message: %v", err)
	}
}

// A read before the sweep expires the ask too, once.
func TestAReadExpiresADueAskOnce(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	r.clock = r.clock.Add(Lifetime)
	for range 2 {
		if got, _ := r.svc.Get(ctx, r.account, v.ID); got.Status != StatusExpired {
			t.Fatalf("read at expiry: %s", got.Status)
		}
	}
	if n, _ := r.svc.ExpireDue(ctx); n != 0 {
		t.Fatalf("the sweep after a read expired %d", n)
	}
	if got := strings.Join(r.audit, ","); got != "owner ask_create ok,system ask_expire ok" {
		t.Fatalf("audit %s", got)
	}
}

// A message the owner writes to the contact goes to the thread of their open ask, even when another
// thread is newer, and answers it with what was written.
func TestTheOwnersOwnMessageAnswersTheContactsOpenAsk(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	newer, err := r.msg.Record(ctx, r.account, bob, messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m9", Text: "another topic"})
	if err != nil || newer.ThreadID == r.thread {
		t.Fatalf("a second thread: %+v %v", newer, err)
	}
	var routed []messaging.Input
	plain := func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
		routed = append(routed, in)
		return r.msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
	}
	send := r.svc.OwnerSend(plain)
	if _, err := send(ctx, r.account, bob, messaging.Input{MsgID: "ui-1", ThreadID: newer.ThreadID, Text: "Let me check my diary", Origin: messaging.OriginPortal}); err != nil {
		t.Fatal(err)
	}
	if len(routed) != 1 || routed[0].ThreadID != r.thread {
		t.Fatalf("the owner's message went to %+v, want the ask's thread %s", routed, r.thread)
	}
	got, _ := r.svc.Get(ctx, r.account, v.ID)
	if got.Status != StatusAnswered || got.AnswerText != `Ana wrote: "Let me check my diary"` {
		t.Fatalf("after the owner's message: %+v", got)
	}
	// With no open ask, a message goes where it was sent, and answers nothing.
	if _, err := send(ctx, r.account, bob, messaging.Input{MsgID: "ui-2", ThreadID: newer.ThreadID, Text: "and another", Origin: messaging.OriginPortal}); err != nil {
		t.Fatal(err)
	}
	if routed[1].ThreadID != newer.ThreadID {
		t.Fatalf("with no open ask the message went to %s", routed[1].ThreadID)
	}
	// A send the node refused outright (not recorded) answers nothing.
	v2, err := r.svc.Ask(ctx, r.account, newer.ThreadID, "m9", []byte(validAsks["the story's ask"]))
	if err != nil {
		t.Fatal(err)
	}
	refusing := r.svc.OwnerSend(func(context.Context, string, string, messaging.Input) (messaging.Result, error) {
		return messaging.Result{}, refusal.Conflict("not serving", nil)
	})
	if _, err := refusing(ctx, r.account, bob, messaging.Input{MsgID: "ui-3", Text: "x", Origin: messaging.OriginPortal}); err == nil {
		t.Fatal("the refusal was swallowed")
	}
	if got, _ := r.svc.Get(ctx, r.account, v2.ID); got.Status != StatusOpen {
		t.Fatalf("a refused send answered the ask: %+v", got)
	}
	// An ask past its time catches nothing: the message goes where it was sent.
	r.clock = r.clock.Add(Lifetime)
	if _, err := send(ctx, r.account, bob, messaging.Input{MsgID: "ui-4", ThreadID: r.thread, Text: "late", Origin: messaging.OriginPortal}); err != nil {
		t.Fatal(err)
	}
	if last := routed[len(routed)-1]; last.ThreadID != r.thread {
		t.Fatalf("a message went to the expired ask's thread %s", last.ThreadID)
	}
	if got, _ := r.svc.Get(ctx, r.account, v2.ID); got.Status != StatusExpired || got.AnswerText != "" {
		t.Fatalf("a message answered an expired ask: %+v", got)
	}
}

// A file the owner sends the contact answers their open ask too, on its thread.
func TestTheOwnersFileAnswersTheContactsOpenAsk(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	var thread string
	send := r.svc.OwnerSendMedia(func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error) {
		thread = in.ThreadID
		return r.msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
	})
	if _, err := send(ctx, r.account, bob, messaging.Input{MsgID: "ui-f", Origin: messaging.OriginPortal}, "diary.pdf", "application/pdf", []byte("%PDF")); err != nil {
		t.Fatal(err)
	}
	if thread != r.thread {
		t.Fatalf("the file went to %q, want %s", thread, r.thread)
	}
	if got, _ := r.svc.Get(ctx, r.account, v.ID); got.AnswerText != `Ana sent a file: "diary.pdf"` {
		t.Fatalf("after the file: %+v", got)
	}
}

// A notice is posted, never expires, and nothing answers or withdraws it.
func TestANoticeIsPostedAndStays(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	n, err := r.svc.Notify(ctx, r.account, r.thread, "m1", []byte(validNotices["done for you"]))
	if err != nil {
		t.Fatal(err)
	}
	if n.Kind != KindNotice || n.Status != StatusPosted || n.ExpiresAt != 0 {
		t.Fatalf("the notice: %+v", n)
	}
	// An ask about the same message is another thing, and the notice does not hold the thread.
	r.ask(validAsks["the story's ask"])
	r.clock = r.clock.Add(10 * Lifetime)
	if got, _ := r.svc.Get(ctx, r.account, n.ID); got.Status != StatusPosted {
		t.Fatalf("a notice after ten lifetimes: %s", got.Status)
	}
	if _, err := r.svc.Answer(ctx, r.account, n.ID, act("x", "tldr", `{}`)); codeOf(err) != "conflict" {
		t.Fatalf("an answer to a notice: %v", err)
	}
	if _, err := r.svc.Withdraw(ctx, r.account, n.ID); codeOf(err) != "conflict" {
		t.Fatalf("a withdraw of a notice: %v", err)
	}
	var stored []map[string]json.RawMessage
	if err := json.Unmarshal(n.Surface, &stored); err != nil || len(stored) != 2 {
		t.Fatalf("the stored surface: %s %v", n.Surface, err)
	}
}

// A thread's asks and notices go with it when the owner deletes it.
func TestDeletingAThreadDeletesItsAsks(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	v := r.ask(validAsks["the story's ask"])
	if _, err := r.msg.DeleteThread(ctx, r.account, r.thread); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Get(ctx, r.account, v.ID); !errors.Is(err, store.ErrNotFound) && codeOf(err) != "not_found" {
		t.Fatalf("the deleted thread's ask: %v", err)
	}
}

// A list narrows to one thread, and to its open asks; a thread with another contact's filter, or a
// thread that is not there, lists nothing.
func TestAListNarrowsToOneThread(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	first := r.ask(validAsks["the story's ask"])
	other, err := r.msg.Record(ctx, r.account, bob, messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m7", Text: "another topic"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.svc.Ask(ctx, r.account, other.ThreadID, "m7", []byte(validAsks["the story's ask"]))
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.svc.Notify(ctx, r.account, r.thread, "m1", []byte(validNotices["a line"]))
	if err != nil {
		t.Fatal(err)
	}
	ids := func(f Filter) string {
		l, err := r.svc.List(ctx, r.account, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, v := range l {
			out = append(out, v.ID)
		}
		return strings.Join(out, ",")
	}
	if got, want := ids(Filter{Thread: r.thread}), first.ID+","+n.ID; got != want {
		t.Fatalf("the thread's: %s, want %s", got, want)
	}
	if got := ids(Filter{Thread: r.thread, Open: true}); got != first.ID {
		t.Fatalf("the thread's open: %s, want %s", got, first.ID)
	}
	if got := ids(Filter{Thread: other.ThreadID}); got != second.ID {
		t.Fatalf("the other thread's: %s", got)
	}
	if got := ids(Filter{Thread: r.thread, Contact: "sha256:someone-else"}); got != "" {
		t.Fatalf("a thread under another contact's filter: %s", got)
	}
	if got := ids(Filter{Thread: "0123456789abcdef0123456789abcdef"}); got != "" {
		t.Fatalf("a thread that is not there: %s", got)
	}
}
