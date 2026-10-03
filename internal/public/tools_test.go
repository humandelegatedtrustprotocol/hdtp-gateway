package public

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/calendar"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

type fakeCalendar struct {
	slots  []calendar.Slot
	booked calendar.Slot
	err    error
}

func (f *fakeCalendar) CheckAvailability(context.Context, time.Time, time.Time, time.Duration) ([]calendar.Slot, error) {
	return f.slots, f.err
}

func (f *fakeCalendar) BookSlot(_ context.Context, _, msgID string, slot calendar.Slot, subject string) (calendar.BookingAck, error) {
	f.booked = slot
	return calendar.BookingAck{BookingID: "bk-" + msgID, ICS: "BEGIN:VCALENDAR\r\nSUMMARY:" + subject + "\r\nEND:VCALENDAR"}, f.err
}

func (f *fakeCalendar) CancelBooking(context.Context, string) error { return f.err }

type fakeStatus struct{ s string }

func (f *fakeStatus) set(v string) { f.s = v }

func (f *fakeStatus) GetStatus(context.Context) (string, error) { return f.s, nil }

// toolEnv is one account with the production tool set behind the real pool.
type toolEnv struct {
	t        *testing.T
	st       store.Store
	acct     store.Account
	kp       *identity.Keypair
	pool     *Pool
	cal      *fakeCalendar
	status   *fakeStatus
	limits   *limitstest.Sidecar
	mu       sync.Mutex
	rows     []string
	outcomes []string
	drops    []string
}

func newToolEnv(t *testing.T) *toolEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "tools.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, acct.ID, kp.Fingerprint, []byte{1}); err != nil {
		t.Fatal(err)
	}
	e := &toolEnv{t: t, st: st, acct: acct, kp: kp, cal: &fakeCalendar{}, status: &fakeStatus{s: "available"}}
	// The card AND the chain that proves it, from one wallet: `redeem_invite` and `get_card` both
	// answer with the chain (HDTP §6.1). This fixture used to wire a `spki` and no chain at all,
	// and every test of those two results passed against an answer no caller could have verified.
	card, _, host := testid.Card(t, "Me", "https://me.example/a/me/mcp", "")
	// This host's limits sidecar, as the node wires it: the pending-request cap, and get_card's
	// call budgets.
	side := limitstest.StartDefault(t)
	e.limits = side
	reg := &Registry{}
	reg.Add(BuiltinEntries(ToolDeps{
		AccountID: acct.ID,
		Contacts: &contacts.Manager{Store: st, AdmitRequest: func(ctx context.Context, accountID string, held int64) error {
			d, err := side.Decide(ctx, accountID, []limits.Charge{limits.PendingIn(held)}, "", time.Now())
			if err != nil || !d.Allowed {
				return contacts.ErrRequestsFull
			}
			return nil
		}},
		Limits: func(ctx context.Context) (Limits, error) {
			calls, err := side.Advertise(ctx, core.DefaultLimitContacts)
			return LimitsWith(calls), err
		},
		Messages: &messaging.Service{Store: st, Bus: messaging.NewBus(st)},
		Media:    &messaging.MediaService{Store: st, Blobs: messaging.BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}},
		Calendar: e.cal,
		Status:   e.status,
		Card:     func(context.Context) (string, string, error) { return card, "sig", nil },
		Chain:    func(context.Context) ([][]byte, error) { return host.Chain, nil },
		Invalidate: func(_ context.Context, _, fpr string) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.drops = append(e.drops, fpr)
			return nil
		},
		// Rows are recorded as the chain stores them — action, resource, outcome —
		// so an assertion on a row is an assertion on what the portal will show.
		Audit: func(a, res, out string) {
			e.mu.Lock()
			e.rows = append(e.rows, strings.TrimSpace(a+" "+res+" "+out))
			e.outcomes = append(e.outcomes, out)
			e.mu.Unlock()
		},
	})...)
	e.pool = NewPool(reg, StoreResolver(st), 8)
	return e
}

// contact inserts a contact at a status with permissions and returns its fpr.
func (e *toolEnv) contact(status string, perms ...string) (string, *identity.Keypair) {
	e.t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		e.t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if _, err := e.st.InsertContact(context.Background(), store.Contact{
		AccountID: e.acct.ID, Fingerprint: kp.Fingerprint, SPKI: spki,
		Status: status, Permissions: perms, PinnedAt: time.Now().Unix(),
	}); err != nil {
		e.t.Fatal(err)
	}
	return kp.Fingerprint, kp
}

func (e *toolEnv) list(fpr string) []string {
	e.t.Helper()
	srv, err := e.pool.ServerFor(context.Background(), e.acct.ID, fpr)
	if err != nil {
		e.t.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		e.t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// call dispatches through Pool.Dispatch — the same guarded path a sealed call
// takes — so the test can present the transport facts the wire would carry.
func (e *toolEnv) call(fpr, tool string, args map[string]any, spki []byte) (*mcp.CallToolResult, error) {
	e.t.Helper()
	return e.callAs(nil, fpr, tool, args, spki)
}

// callAs is call with a proven 2.0 identity: `guest` is the peer whose chain the
// caller presented, which is what the guest tools pin (HDTP §14.2 rule 6). A bare
// key proves nothing now, so a guest tool reached without one answers
// identity_required — which is why every guest-tier test here has to bring a peer.
func (e *toolEnv) callAs(guest *testid.Host, fpr, tool string, args map[string]any, spki []byte) (*mcp.CallToolResult, error) {
	e.t.Helper()
	ctx := context.Background()
	if spki != nil {
		ctx = WithFacts(ctx, TransportFacts{ClientCertSPKI: spki, ClientCertFingerprint: hdtpidentity.Fingerprint(spki)})
	}
	if guest != nil {
		ctx = WithEnvelopeFacts(ctx, &EnvelopeFacts{
			From: guest.RootFpr, SPKI: guest.Key.Public().SPKI,
			Endpoint: guest.Endpoint, Leaf: guest.LeafDER, Guest: fpr == "",
		})
	}
	params, err := json.Marshal(map[string]any{"name": tool, "arguments": args})
	if err != nil {
		return nil, err
	}
	raw, err := e.pool.Dispatch(ctx, e.acct.ID, fpr, Payload{Method: "tools/call", Params: params})
	if err != nil {
		return nil, err
	}
	var res mcp.CallToolResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// countMessages counts every message stored for the account.
func (e *toolEnv) countMessages() int {
	ctx := context.Background()
	threads, _ := e.st.ListThreadsByAccount(ctx, e.acct.ID)
	n := 0
	for _, th := range threads {
		msgs, _ := e.st.ListMessagesByThread(ctx, e.acct.ID, th.ID)
		n += len(msgs)
	}
	return n
}

func body(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// AC: the surface each tier sees, from the production entries.
func TestBuiltinToolSurfacePerTier(t *testing.T) {
	e := newToolEnv(t)

	guest := e.list("")
	if len(guest) != 2 || !has(guest, "redeem_invite") || !has(guest, "request_contact") {
		t.Fatalf("guest surface: %v", guest)
	}

	pendingFpr, _ := e.contact("pending_out")
	pending := e.list(pendingFpr)
	if len(pending) != 2 || !has(pending, "contact_accepted") || !has(pending, "contact_rejected") {
		t.Fatalf("pending surface: %v", pending)
	}

	// a contact with NO permissions still gets the three always-tools
	bare, _ := e.contact("active")
	got := e.list(bare)
	if len(got) != 3 || !has(got, "get_card") || !has(got, "update_contact") || !has(got, "remove_contact") {
		t.Fatalf("permissionless contact surface: %v", got)
	}

	// permissions add exactly their tools
	full, _ := e.contact("active", "message.text", "message.media", "status.view",
		"calendar.availability", "calendar.book")
	got = e.list(full)
	for _, want := range []string{"send_message", "send_media", "get_status",
		"check_availability", "book_slot", "cancel_booking", "get_card"} {
		if !has(got, want) {
			t.Fatalf("%s missing from a fully-permitted contact: %v", want, got)
		}
	}

	// a permission flip is reflected after the pool drops the cached server
	if err := e.st.UpdateContactPermissions(context.Background(), e.acct.ID, full, []string{"message.text"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.Invalidate(context.Background(), e.acct.ID, full); err != nil {
		t.Fatal(err)
	}
	got = e.list(full)
	if has(got, "book_slot") || !has(got, "send_message") {
		t.Fatalf("after revoking calendar.book: %v", got)
	}

	// blocked is silent demotion: EXACTLY the guest surface
	blocked, _ := e.contact("blocked", "message.text")
	if b := e.list(blocked); len(b) != 2 || !has(b, "redeem_invite") {
		t.Fatalf("blocked surface: %v", b)
	}
}

// AC: a permitted call executes against the node's own store.
func TestSendMessageRecordsAndIsIdempotent(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active", "message.text")

	res, err := e.call(fpr, "send_message", map[string]any{
		"msg_id": "m-1", "text": "hello", "sender": "human", "topic": "lunch",
	}, nil)
	if err != nil || res.IsError {
		t.Fatalf("send_message: %v %s", err, body(t, res))
	}
	var first struct {
		ThreadID string `json:"thread_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal([]byte(body(t, res)), &first); err != nil {
		t.Fatalf("body: %s", body(t, res))
	}
	if first.ThreadID == "" || first.Status == "" {
		t.Fatalf("result: %+v", first)
	}
	// same msg_id is acknowledged, not re-executed
	res2, _ := e.call(fpr, "send_message", map[string]any{"msg_id": "m-1", "text": "hello"}, nil)
	if res2.IsError {
		t.Fatalf("replay refused: %s", body(t, res2))
	}
	if n := e.countMessages(); n != 1 {
		t.Fatalf("replay stored %d messages", n)
	}
	// the label the PEER claims is honored, but only from the fixed vocabulary
	if bad, _ := e.call(fpr, "send_message", map[string]any{"msg_id": "m-2", "text": "x", "sender": "root"}, nil); !bad.IsError ||
		!strings.Contains(body(t, bad), "bad_request") {
		t.Fatalf("bogus sender label accepted: %s", body(t, bad))
	}
}

// AC: caps are enforced at the boundary — rejected, never silently truncated.
func TestBoundaryCapsRejectOversizedInput(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active", "message.text", "message.media")

	res, _ := e.call(fpr, "send_message", map[string]any{
		"msg_id": "big", "text": strings.Repeat("a", 16*1024+1),
	}, nil)
	if !res.IsError || !strings.Contains(body(t, res), "too_large") {
		t.Fatalf("16 KiB+1 text: %s", body(t, res))
	}
	if n := e.countMessages(); n != 0 {
		t.Fatal("an over-cap message was stored")
	}
	// inline media over 5 MiB
	oversized := base64.StdEncoding.EncodeToString(make([]byte, 5*1024*1024+1))
	res, _ = e.call(fpr, "send_media", map[string]any{
		"msg_id": "m", "thread_id": "t", "filename": "x.bin", "mime": "application/octet-stream", "data": oversized,
	}, nil)
	if !res.IsError || !strings.Contains(body(t, res), "too_large") {
		t.Fatalf("5 MiB+1 inline media: %s", body(t, res))
	}
	// a note over 1 KiB on the guest tool
	card := testid.CardFor(t, "Stranger", "https://s.example/a/s/mcp")
	res, _ = e.call("", "request_contact", map[string]any{
		"card": card, "note": strings.Repeat("n", 1025),
	}, nil)
	if !res.IsError || !strings.Contains(body(t, res), "too_large") {
		t.Fatalf("1 KiB+1 note: %s", body(t, res))
	}
}

// AC: redeeming pins the key the caller PROVED and drops its cached guest surface.
func TestRedeemInvitePinsProvenKeyAndInvalidates(t *testing.T) {
	ctx := context.Background()
	e := newToolEnv(t)
	cm := &contacts.Manager{Store: e.st}
	token, _, err := cm.CreateInvite(ctx, e.acct.ID, contacts.InviteOptions{AutoAccept: true, MaxUses: 1, Preset: "friend"})
	if err != nil {
		t.Fatal(err)
	}
	peerCard, _, peerHost := testid.Card(t, "Peer", "https://p.example/a/p/mcp", "")
	peerSPKI := peerHost.Key.Public().SPKI

	res, err := e.callAs(peerHost, "", "redeem_invite", map[string]any{"token": token, "card": peerCard}, peerSPKI)
	if err != nil || res.IsError {
		t.Fatalf("redeem: %v %s", err, body(t, res))
	}
	var out struct {
		Status string   `json:"status"`
		Card   string   `json:"card"`
		Chain  []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(body(t, res)), &out); err != nil {
		t.Fatalf("body: %s", body(t, res))
	}
	if out.Status != "accepted" || out.Card == "" {
		t.Fatalf("redeem result: %+v", out)
	}
	// HDTP §6.1: `redeem_invite` answers with the issuer's signed card AND its chain, so the
	// redeemer pins a root it can verify. This asserted a `spki` member instead — 1.2's key beside
	// the card — and the result carried no chain at all, which no test noticed because the
	// fixture never wired one.
	if len(out.Chain) != 2 {
		t.Fatalf("the result must carry the issuer's [leaf, root], got %d certificates", len(out.Chain))
	}
	issued, err := contacts.ValidateInbound(out.Card)
	if err != nil {
		t.Fatalf("the card it returned does not validate: %v", err)
	}
	chain := [][]byte{testid.DER(t, out.Chain[0]), testid.DER(t, out.Chain[1])}
	vr := hdtpidentity.ValidateChain(chain, hdtpidentity.ChainOpts{Now: time.Now(), ExpectedRoot: issued.Key, ExpectedEndpoint: issued.Endpoint})
	if !vr.OK {
		t.Fatalf("the chain it returned fails rule %d: %s", vr.Rule, vr.Reason)
	}
	if !bytes.Equal(chain[0], issued.Cert) {
		t.Fatal("the chain's leaf is not the certificate on the card it came with")
	}
	if strings.Contains(body(t, res), `"spki"`) {
		t.Fatal("the result still carries `spki`, a member HDTP §6.1 does not define")
	}
	// the contact is pinned with the FULL proven key, not just its hash
	c, err := e.st.GetContact(ctx, e.acct.ID, peerHost.RootFpr)
	if err != nil || c.Status != "active" || len(c.SPKI) == 0 {
		t.Fatalf("pinned contact: %+v %v", c, err)
	}
	// and the promoted caller's cached guest server was dropped
	e.mu.Lock()
	dropped := len(e.drops) == 1 && e.drops[0] == peerHost.RootFpr
	e.mu.Unlock()
	if !dropped {
		t.Fatalf("pool not invalidated: %v", e.drops)
	}
	// a second redemption of a one-time token fails with the HDTP code
	res, _ = e.callAs(peerHost, "", "redeem_invite", map[string]any{"token": token, "card": peerCard}, peerSPKI)
	if !res.IsError || !strings.Contains(body(t, res), "invite_invalid") {
		t.Fatalf("token reuse: %s", body(t, res))
	}
	// redeeming with no proven key at all
	res, _ = e.call("", "redeem_invite", map[string]any{"token": token, "card": peerCard}, nil)
	if !res.IsError || !strings.Contains(body(t, res), "identity_required") {
		t.Fatalf("keyless redemption: %s", body(t, res))
	}
}

// AC: calendar tools speak HDTP's vocabulary and the ≤5-slot cap holds.
func TestCalendarToolsRespectSlotCapAndBookIdempotently(t *testing.T) {
	e := newToolEnv(t)
	base := time.Now().UTC().Truncate(time.Hour)
	for i := 0; i < 5; i++ {
		e.cal.slots = append(e.cal.slots, calendar.Slot{
			Start: base.Add(time.Duration(i) * time.Hour),
			End:   base.Add(time.Duration(i)*time.Hour + 30*time.Minute),
		})
	}
	fpr, _ := e.contact("active", "calendar.availability", "calendar.book")

	res, err := e.call(fpr, "check_availability", map[string]any{
		"window":       map[string]any{"from": time.Now().Format(time.RFC3339), "to": time.Now().Add(48 * time.Hour).Format(time.RFC3339), "tz": "UTC"},
		"duration_min": 30,
	}, nil)
	if err != nil || res.IsError {
		t.Fatalf("check_availability: %v %s", err, body(t, res))
	}
	var av struct {
		Slots []Slot `json:"slots"`
	}
	if err := json.Unmarshal([]byte(body(t, res)), &av); err != nil {
		t.Fatalf("body: %s", body(t, res))
	}
	if len(av.Slots) != 5 {
		t.Fatalf("slots: %d", len(av.Slots))
	}

	res, err = e.call(fpr, "book_slot", map[string]any{
		"msg_id": "b-1", "subject": "coffee", "slot": av.Slots[0],
	}, nil)
	if err != nil || res.IsError {
		t.Fatalf("book_slot: %v %s", err, body(t, res))
	}
	var ack calendar.BookingAck
	if err := json.Unmarshal([]byte(body(t, res)), &ack); err != nil {
		t.Fatalf("body: %s", body(t, res))
	}
	if ack.BookingID != "bk-b-1" || !strings.Contains(ack.ICS, "coffee") {
		t.Fatalf("ack: %+v", ack)
	}
	if !e.cal.booked.Start.Equal(base) {
		t.Fatalf("booked the wrong slot: %+v", e.cal.booked)
	}
	if av.Slots[0].TZ != "UTC" {
		t.Fatalf("slot zone not stated: %+v", av.Slots[0])
	}
	// a missing window is a bad_request, not a panic or a silent default
	res, _ = e.call(fpr, "check_availability", map[string]any{"duration_min": 30}, nil)
	if !res.IsError || !strings.Contains(body(t, res), "bad_request") {
		t.Fatalf("windowless availability: %s", body(t, res))
	}
}

// AC: a capability with no provider configured is `unavailable`, never a crash.
func TestUnconfiguredCapabilityIsUnavailable(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "bare.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acct, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "bare", DisplayName: "Bare", Algo: "p256"})
	card := testid.CardFor(t, "Bare", "https://b.example/a/bare/mcp")
	reg := &Registry{}
	reg.Add(BuiltinEntries(ToolDeps{
		AccountID: acct.ID,
		Contacts:  &contacts.Manager{Store: st},
		Messages:  &messaging.Service{Store: st},
		Card:      func(context.Context) (string, string, error) { return card, "sig", nil },
	})...) // no Calendar, no Status, no Media
	pool := NewPool(reg, StoreResolver(st), 4)
	peer, _ := identity.Generate(identity.AlgoP256)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: peer.Fingerprint, Status: "active",
		Permissions: []string{"calendar.book", "status.view", "message.media"},
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := pool.ServerFor(ctx, acct.ID, peer.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	ct, stt := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, stt, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	// The tools are still listed (the switchboard grants them) but answer
	// `unavailable` — the HDTP code for a capability an implementation is
	// currently withholding.
	for _, tool := range []string{"book_slot", "get_status", "send_media"} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"msg_id": "x"}})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if !res.IsError || !strings.Contains(body(t, res), "unavailable") {
			t.Fatalf("%s with no provider: %s", tool, body(t, res))
		}
	}
}

// AC: always-available contact management works and is not permission-gated.
func TestAlwaysToolsAtContactTier(t *testing.T) {
	ctx := context.Background()
	e := newToolEnv(t)
	fpr, kp := e.contact("active") // no permissions at all

	res, err := e.call(fpr, "get_card", map[string]any{}, nil)
	if err != nil || res.IsError {
		t.Fatalf("get_card: %v %s", err, body(t, res))
	}
	if !strings.Contains(body(t, res), "X-PACT-CERT") {
		t.Fatalf("get_card body: %s", body(t, res))
	}

	res, err = e.call(fpr, "remove_contact", map[string]any{}, nil)
	if err != nil || res.IsError {
		t.Fatalf("remove_contact: %v %s", err, body(t, res))
	}
	if _, err := e.st.GetContact(ctx, e.acct.ID, kp.Fingerprint); err == nil {
		t.Fatal("remove_contact left the contact in place")
	}
}

// AC (SPEC §5.4, §9.1): a blocked caller is served exactly as a stranger — same
// tool list, same answers. Anything else tells them they were blocked.
func TestBlockedCallerIsIndistinguishableFromAStranger(t *testing.T) {
	ctx := context.Background()
	e := newToolEnv(t)

	blockedKP, _ := identity.Generate(identity.AlgoP256)
	blockedSPKI, _ := x509.MarshalPKIXPublicKey(blockedKP.Signer.Public())
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: blockedKP.Fingerprint, SPKI: blockedSPKI,
		Status: "blocked", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}
	strangerKP, _ := identity.Generate(identity.AlgoP256)
	strangerSPKI, _ := x509.MarshalPKIXPublicKey(strangerKP.Signer.Public())

	// identical surfaces
	bl, str := e.list(blockedKP.Fingerprint), e.list(strangerKP.Fingerprint)
	if len(bl) != len(str) || len(bl) != 2 {
		t.Fatalf("blocked %v vs stranger %v", bl, str)
	}
	for i := range bl {
		if bl[i] != str[i] {
			t.Fatalf("blocked %v vs stranger %v", bl, str)
		}
	}
	// a permitted contact tool is out of reach for the blocked caller, and the
	// refusal is the same one a stranger gets
	blRes, _ := e.call(blockedKP.Fingerprint, "send_message",
		map[string]any{"msg_id": "b-1", "text": "let me in"}, blockedSPKI)
	strRes, _ := e.call(strangerKP.Fingerprint, "send_message",
		map[string]any{"msg_id": "s-1", "text": "hello"}, strangerSPKI)
	if !blRes.IsError || body(t, blRes) != body(t, strRes) {
		t.Fatalf("blocked %s vs stranger %s", body(t, blRes), body(t, strRes))
	}

	// request_contact reads the same to both — the blocked one records nothing.
	// Each brings its own identity: a guest tool pins what the chain proved, and the
	// blocked caller has to arrive as the root it is blocked under.
	blCard, _, blHost := testid.Card(t, "Blocked", "https://b.example/a/b/mcp", "")
	strCard, _, strHost := testid.Card(t, "Stranger", "https://s.example/a/s/mcp", "")
	// The root the chain proves is the one that has to be blocked. This half used to block
	// blockedKP's fingerprint and call as blHost, a root nobody had blocked — so it compared a
	// stranger with a stranger and passed whatever the blocked branch did.
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: blHost.RootFpr, SPKI: blHost.Key.Public().SPKI,
		Status: "blocked", Endpoint: blHost.Endpoint, Leaf: blHost.LeafDER, PinnedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	blRes, _ = e.callAs(blHost, "", "request_contact", map[string]any{"card": blCard, "note": "hi"}, blockedSPKI)
	strRes, _ = e.callAs(strHost, "", "request_contact", map[string]any{"card": strCard, "note": "hi"}, strangerSPKI)
	if blRes.IsError || body(t, blRes) != body(t, strRes) {
		t.Fatalf("request_contact blocked %s vs stranger %s", body(t, blRes), body(t, strRes))
	}
	// ...and the owner never sees a request from the blocked caller
	c, err := e.st.GetContact(ctx, e.acct.ID, blHost.RootFpr)
	if err != nil || c.Status != "blocked" {
		t.Fatalf("blocked caller's status changed: %+v %v", c, err)
	}
	// a repeat request from the (now pending_in) stranger is pending_approval
	strRes, _ = e.callAs(strHost, "", "request_contact", map[string]any{"card": strCard, "note": "hi again"}, strangerSPKI)
	if !strRes.IsError || !strings.Contains(body(t, strRes), "pending_approval") {
		t.Fatalf("duplicate request: %s", body(t, strRes))
	}
}

// AC (P9-04): HDTP §12 names `blocked_or_unknown` as the guest-tier catch-all,
// and it was specified everywhere and emitted nowhere — a guest got
// `permission_denied` on the sealed path and the SDK's own unknown-tool error
// on the plaintext one. The two paths must agree, and at guest tier the answer
// must not distinguish "you may not" from "no such tool".
func TestGuestRefusalIsBlockedOrUnknownOnBothPaths(t *testing.T) {
	e := newToolEnv(t)
	blocked, blockedKP := e.contact("blocked", "message.text")
	_ = blockedKP
	stranger, _ := e.contact("pending_in") // resolves to guest tier

	for _, fpr := range []string{"", blocked, stranger} {
		res, err := e.call(fpr, "send_message", map[string]any{"msg_id": "x", "text": "hi"}, nil)
		if err != nil {
			t.Fatalf("caller %q: %v", fpr, err)
		}
		if !res.IsError || !strings.Contains(body(t, res), "blocked_or_unknown") {
			t.Fatalf("guest-tier caller %q got %q, want blocked_or_unknown", fpr, body(t, res))
		}
	}

	// a CONTACT is known, so a tool their switchboard does not grant is an
	// honest permission_denied rather than the catch-all
	contact, _ := e.contact("active", "message.text")
	res, err := e.call(contact, "book_slot", map[string]any{"msg_id": "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(body(t, res), "permission_denied") {
		t.Fatalf("a known contact got %q, want permission_denied", body(t, res))
	}
}

// AC (P9-04): the card a peer receives over MCP carries a signature, as the one
// served over the invite landing page always did.
func TestCardsAreSignedOverMCPToo(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active")
	res, err := e.call(fpr, "get_card", map[string]any{}, nil)
	if err != nil || res.IsError {
		t.Fatalf("get_card: %v %s", err, body(t, res))
	}
	var out struct {
		Card    string `json:"card"`
		CardSig string `json:"card_sig"`
	}
	if err := json.Unmarshal([]byte(body(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Card == "" || out.CardSig == "" {
		t.Fatalf("the card went out unsigned: %+v", out)
	}
}

// A unit test on the redactor proves the rules; this proves they are on the
// path. The audit is append-only and hash-chained, so a token that reaches it
// stays there — the helper that builds a refusal's reason has to be the place
// that strips it, not a habit at each of the twelve call sites.
func TestRefusalReasonsAreRedactedBeforeTheyAreAudited(t *testing.T) {
	err := errors.New(`Post "https://owner:harness-pw@cal:5232/": 401 Authorization: Bearer ya29.SECRETvalue123`)
	got := why(err)
	for _, secret := range []string{"harness-pw", "ya29.SECRET"} {
		if strings.Contains(got, secret) {
			t.Fatalf("a credential reached the audit text: %q", got)
		}
	}
	if !strings.Contains(got, "why:") || !strings.Contains(got, "401") {
		t.Fatalf("the reason itself was lost, which is the whole point of recording it: %q", got)
	}
}

// Truncation must not be able to leave half a secret behind: redact first.
func TestALongReasonIsRedactedBeforeItIsTruncated(t *testing.T) {
	long := strings.Repeat("upstream said no. ", 20) + "token=abcdefghijklmnopqrstuvwxyz0123456789"
	if got := why(errors.New(long)); strings.Contains(got, "abcdefghij") {
		t.Fatalf("a truncated secret survived: %q", got)
	}
}

// The outcome column is a verdict, not a place to put things. It is what the
// portal colours, counts and filters by, so a caller fingerprint, a booking id
// or a failure sentence in that column makes every row its own category and
// hides real refusals from the owner — which is exactly what it used to do.
// Locators and reasons belong in the resource.
func TestAuditOutcomesAreSingleVerdicts(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active", "message.text", "message.media", "status.view",
		"calendar.availability", "calendar.book")

	// A spread of the surface: successes, a refusal, and the paths that carry a
	// reason, so the assertion sees the shapes that used to come out malformed.
	_, _ = e.call(fpr, "get_card", map[string]any{}, nil)
	_, _ = e.call(fpr, "send_message", map[string]any{"msg_id": "m-1", "text": "hello"}, nil)
	_, _ = e.call(fpr, "send_message", map[string]any{"msg_id": "m-2", "text": strings.Repeat("x", MaxTextBytes+1)}, nil)
	_, _ = e.call(fpr, "get_status", map[string]any{}, nil)
	_, _ = e.call(fpr, "book_slot", map[string]any{"msg_id": "b-1",
		"slot": map[string]any{"start": "2030-01-01T10:00:00Z", "end": "2030-01-01T10:30:00Z"}}, nil)

	// A failure whose message carries a credential: the reason must reach the
	// trail, on the resource, with the secret already gone.
	e.cal.err = errors.New("upstream refused: Authorization: Bearer sk-live-not-a-real-key")
	_, _ = e.call(fpr, "book_slot", map[string]any{"msg_id": "b-2",
		"slot": map[string]any{"start": "2030-01-01T11:00:00Z", "end": "2030-01-01T11:30:00Z"}}, nil)

	e.mu.Lock()
	outcomes := append([]string(nil), e.outcomes...)
	rows := append([]string(nil), e.rows...)
	e.mu.Unlock()
	if len(outcomes) == 0 {
		t.Fatal("nothing was audited")
	}
	verdict := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for i, out := range outcomes {
		if !verdict.MatchString(out) {
			t.Errorf("outcome %q is not a single verdict (row: %s)", out, rows[i])
		}
	}
	var carried bool
	for _, r := range rows {
		if strings.Contains(r, "why:") {
			carried = true
			if strings.Contains(r, "sk-live-not-a-real-key") || strings.Contains(r, "Bearer") {
				t.Errorf("a credential reached the audit trail: %s", r)
			}
		}
	}
	if !carried {
		t.Error("a failure was audited with no reason recorded")
	}
}

// HDTP §6.2: get_status answers from a fixed four-value vocabulary, and an
// upstream presence source that knows richer states maps them to busy — at the
// wire, so every StatusSource implementation is covered by the one clamp.
func TestGetStatusClampsToTheSpecVocabulary(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active", "status.view")
	for upstream, want := range map[string]string{
		"available": "available", "busy": "busy", "dnd": "dnd", "offline": "offline",
		"in-a-meeting": "busy", "": "busy", "AVAILABLE": "busy",
	} {
		e.status.set(upstream)
		res, err := e.call(fpr, "get_status", map[string]any{}, nil)
		if err != nil || res.IsError {
			t.Fatalf("get_status(%q): %v %v", upstream, err, res)
		}
		if got := body(t, res); !strings.Contains(got, `"status":"`+want+`"`) {
			t.Fatalf("upstream %q went to the wire as %s, want %q", upstream, got, want)
		}
	}
}

// HDTP §12: the limits in force are advertised on get_card — a peer discovers
// an operator-tuned budget from the card, not from rate_limited.
func TestGetCardAdvertisesTheLimitsInForce(t *testing.T) {
	e := newToolEnv(t)
	fpr, _ := e.contact("active", "message.text")
	res, err := e.call(fpr, "get_card", map[string]any{}, nil)
	if err != nil || res.IsError {
		t.Fatalf("get_card: %v %v", err, res)
	}
	var got struct {
		Limits Limits `json:"limits"`
	}
	if err := json.Unmarshal([]byte(body(t, res)), &got); err != nil {
		t.Fatalf("body: %s", body(t, res))
	}
	r := limitstest.DefaultRules(t)
	want := Limits{
		TextBytes: MaxTextBytes, NoteBytes: MaxNoteBytes, MediaInlineBytes: MaxInlineData,
		AvailabilitySlots: calendar.MaxSlots, InviteTTLDays: int(contacts.MaxInviteTTL / (24 * time.Hour)),
		Advertised: limits.Advertised{
			ContactCallsPerSecond: r.ContactCallsPerSecond, ContactBurst: r.ContactBurst,
			IdentityCallsPerSecond:  math.Max(1, math.Min(float64(core.DefaultLimitContacts)*r.ContactCallsPerSecond, r.IdentityCapacityPerSecond)),
			GuestCallsPerHour:       r.GuestCallsPerHour,
			GuestSourceCallsPerHour: r.GuestSourceCallsPerHour,
		},
	}
	if got.Limits != want {
		t.Fatalf("get_card advertised %+v; the sidecar enforces %+v", got.Limits, want)
	}
	// The members' wire names: a card that renamed one would pass the comparison above and still
	// say nothing a peer reads.
	for _, m := range []string{"text_bytes", "note_bytes", "media_inline_bytes", "availability_slots", "invite_ttl_days",
		"contact_calls_per_second", "contact_burst", "identity_calls_per_second", "guest_calls_per_hour", "guest_source_calls_per_hour"} {
		if !strings.Contains(body(t, res), `"`+m+`":`) {
			t.Fatalf("get_card's limits have no %s: %s", m, body(t, res))
		}
	}
	// No sidecar, no card: there is no compiled-in copy of the budgets to advertise instead.
	e.limits.Stop()
	if res, err := e.call(fpr, "get_card", map[string]any{}, nil); err != nil || !res.IsError || !strings.Contains(body(t, res), `"unavailable"`) {
		t.Fatalf("get_card with the sidecar down: %v %s, want unavailable", err, body(t, res))
	}
	if strings.Contains(body(t, res), "contact_calls_per_hour") {
		t.Fatalf("the hourly contact budget is gone from HDTP §12 and is still advertised: %s", body(t, res))
	}
}

// A blocked root holding a live link of ours reads it exactly as a stranger holding the same
// link does (HDTP §12, review N-08 / P-22). It used to spend a use, fail the insert and answer
// `invite_invalid` — which told the caller it was known here, and cost the owner the use.
func TestRedeemByABlockedRootReadsAsAStrangersRedemption(t *testing.T) {
	ctx := context.Background()
	e := newToolEnv(t)
	m := &contacts.Manager{Store: e.st}
	token, inv, err := m.CreateInvite(ctx, e.acct.ID, contacts.InviteOptions{MaxUses: 5, Label: "badge"})
	if err != nil {
		t.Fatal(err)
	}
	blCard, _, blHost := testid.Card(t, "Blocked", "https://b.example/a/b/mcp", "")
	blSPKI := blHost.Key.Public().SPKI
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acct.ID, Fingerprint: blHost.RootFpr, SPKI: blHost.Key.Public().SPKI,
		Status: "blocked", Endpoint: blHost.Endpoint, Leaf: blHost.LeafDER, PinnedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	strCard, _, strHost := testid.Card(t, "Stranger", "https://s.example/a/s/mcp", "")
	strSPKI := strHost.Key.Public().SPKI

	blRes, err := e.callAs(blHost, "", "redeem_invite", map[string]any{"token": token, "card": blCard}, blSPKI)
	if err != nil {
		t.Fatal(err)
	}
	strRes, err := e.callAs(strHost, "", "redeem_invite", map[string]any{"token": token, "card": strCard}, strSPKI)
	if err != nil {
		t.Fatal(err)
	}
	if blRes.IsError || body(t, blRes) != body(t, strRes) {
		t.Fatalf("redeem_invite: blocked %s vs stranger %s", body(t, blRes), body(t, strRes))
	}
	// Nothing the blocked root did is visible to the owner: its row is as it was, and only the
	// stranger's redemption spent a use.
	if c, _ := e.st.GetContact(ctx, e.acct.ID, blHost.RootFpr); c.Status != "blocked" || c.InviteID != "" {
		t.Fatalf("the blocked row was written: %+v", c)
	}
	list, _ := e.st.ListInvites(ctx, e.acct.ID)
	if len(list) != 1 || list[0].ID != inv.ID || list[0].Uses != 1 {
		t.Fatalf("uses after one stranger and one blocked root: %+v, want 1", list)
	}
	// The control: the stranger's redemption did land.
	if c, err := e.st.GetContact(ctx, e.acct.ID, strHost.RootFpr); err != nil || c.Status != "pending_in" {
		t.Fatalf("the stranger's redemption did not land: %+v %v", c, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !slices.Contains(e.rows, "redeem_invite caller:"+blHost.RootFpr+" blocked_silent") {
		t.Errorf("the audit trail does not record the blocked redemption: %v", e.rows)
	}
}
