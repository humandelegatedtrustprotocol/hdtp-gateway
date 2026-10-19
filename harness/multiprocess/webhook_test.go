package multiprocess

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/owner"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/peer"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/webhooks"
)

// posted is one request a receiver got.
type posted struct {
	header http.Header
	body   string
}

// receiver is the owner's agent's webhook endpoint: it keeps what it is posted and answers 204.
type receiver struct {
	*httptest.Server
	mu    sync.Mutex
	posts []posted
	got   chan struct{}
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	rc := &receiver{got: make(chan struct{}, 16)}
	rc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.posts = append(rc.posts, posted{r.Header.Clone(), string(b)})
		rc.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		rc.got <- struct{}{}
	}))
	t.Cleanup(rc.Close)
	return rc
}

func (rc *receiver) all() []posted {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]posted(nil), rc.posts...)
}

// signedBy is what a receiver checks, written as one would write it from the README's rules and
// not from the node's code: the timestamp within 300 seconds, and a v1 equal to the HMAC-SHA256 of
// `<t>.<body>` under the secret.
func signedBy(secret, header, body string, now time.Time) bool {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	at, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now.Unix()-at > 300 || at-now.Unix() > 300 {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + body))
	want := hex.EncodeToString(m.Sum(nil))
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}

// TestAContactsMessageWakesTheOwnersAgentWithASignedWebhook is the webhooks' scenario (W4 of
// docs/release/webhooks-2026-10-18.md), hermetic: one `hdtp-gateway serve` of the shipped binary on
// SQLite, and a receiver on loopback (ruling A takes one). The endpoint is registered through the
// portal's own route, `POST /webhooks/create`, by the owner's session; the session is minted into
// the store before the process starts, because the passkey ceremony that mints one is the portal
// tests' and the browser tiers'. Then a contact redeems an invite and sends a message, and:
//   - the receiver is posted one message.received, signed with the endpoint's secret, which it
//     verifies, and which a changed body does not pass (the control);
//   - the headers name the event, its id and a delivery the node's log records as delivered;
//   - the envelope's identity is the account's id and its data names the contact, the message and
//     the thread, and read_thread with those two reads the message the contact sent.
func TestAContactsMessageWakesTheOwnersAgentWithASignedWebhook(t *testing.T) {
	bin := binary(t)
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(dir, "keyring.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	s := seed(t, st, kr)
	session, err := auth.New(st).MintSession(ctx, s.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	d := deployment{engine: "sqlite", dirs: [2]string{dir, dir}, limits: limitstest.StartDefault(t).Path}
	a := start(t, bin, "A", d, 0, []string{"HDTP_LOG=off"})
	a.ready(t, s.ownerToken)
	rc := newReceiver(t)
	hookID, secret := registerOnThePortal(t, a, dir, session, s.accountID, rc.URL+"/hdtp/webhook", "message.received")

	bharat, err := peer.NewAgent("bharat")
	if err != nil {
		t.Fatal(err)
	}
	target := peer.Target{Endpoint: identity.EndpointFor(publicURL, s.slug), Dial: a.public, Seal: "required", Root: s.root, Leaf: s.leaf}
	if res, err := bharat.Call(ctx, target, "redeem_invite", map[string]any{"token": s.inviteToken, "card": bharat.Card("required")}, "wh-redeem"); err != nil {
		t.Fatalf("redeem: %v %s", err, res)
	}
	const text = "wake up, there is a message"
	if res, err := bharat.Call(ctx, target, "send_message", map[string]any{"msg_id": "wh-1", "text": text}, "wh-1"); err != nil {
		t.Fatalf("send: %v %s", err, res)
	}

	// The dispatcher posts once this process holds the webhooks lease (a few seconds after it
	// starts) and the change log is read (every 250 ms at the most).
	select {
	case <-rc.got:
	case <-time.After(60 * time.Second):
		t.Fatalf("no webhook was posted within 60 s:\n%s", a.out.String())
	}
	got := rc.all()
	if len(got) != 1 {
		t.Fatalf("%d posts, want 1 (the filter takes message.received only): %+v", len(got), got)
	}
	p := got[0]
	sig := p.header.Get(webhooks.SignatureHeader)
	if !signedBy(secret, sig, p.body, time.Now()) {
		t.Fatalf("the delivery does not verify under the endpoint's secret: %s %s", sig, p.body)
	}
	if signedBy(secret, sig, strings.Replace(p.body, "message.received", "message.delivered", 1), time.Now()) {
		t.Fatal("a changed body verifies: the receiver's check passes anything")
	}
	var env struct {
		ID, Type, Identity string
		CreatedAt          int64 `json:"created_at"`
		Data               struct {
			ThreadID  string `json:"thread_id"`
			MessageID string `json:"message_id"`
			From      string `json:"from"`
		}
	}
	if err := json.Unmarshal([]byte(p.body), &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "message.received" || p.header.Get(webhooks.EventTypeHeader) != env.Type ||
		p.header.Get(webhooks.EventIDHeader) != env.ID || !strings.HasPrefix(env.ID, "evt_") {
		t.Fatalf("the event and its headers disagree: %+v %v", env, p.header)
	}
	if env.Identity != s.accountID || env.Data.From != bharat.Fingerprint() || env.Data.ThreadID == "" || env.Data.MessageID == "" {
		t.Fatalf("the envelope %+v: want identity %s and from %s", env, s.accountID, bharat.Fingerprint())
	}
	if strings.Contains(p.body, text) {
		t.Fatal("the body carries the message's text")
	}

	// The delivery header names the row the node logged it as.
	delivery := p.header.Get(webhooks.DeliveryHeader)
	var status string
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := rawQuery(t, d, "SELECT status FROM webhook_deliveries WHERE id = '"+strings.ReplaceAll(delivery, "'", "")+"' AND endpoint_id = '"+hookID+"'", &status)
		if (err == nil && status == "delivered") || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status != "delivered" || !strings.HasPrefix(delivery, "whd_") {
		t.Fatalf("delivery %q is logged as %q", delivery, status)
	}

	// The agent the webhook woke reads the message with the ids it was given.
	agent, err := owner.Connect(ctx, "http://"+a.internal+"/owner/mcp", s.ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	thread, err := agent.Call(ctx, "read_thread", map[string]any{"account_id": env.Identity, "thread_id": env.Data.ThreadID})
	if err != nil || !strings.Contains(thread, text) {
		t.Fatalf("read_thread with the webhook's ids: %v %s", err, thread)
	}
}

// registerOnThePortal adds an endpoint as the owner does on the portal's Webhooks page: a form post
// to `/webhooks/create` with the owner's session and the double-submit CSRF pair, under the cookie
// names this node's tag gives them (core.NodeTag, from the configuration start writes). It answers
// the endpoint's id and the secret the page shows once.
func registerOnThePortal(t *testing.T, p *proc, dataDir, session, accountID, endpoint, events string) (id, secret string) {
	t.Helper()
	form := url.Values{"account": {accountID}, "url": {endpoint}, "events": {events}}
	req, err := http.NewRequest(http.MethodPost, "http://"+p.internal+"/webhooks/create", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-HDTP-Csrf", "harness-csrf")
	tag := core.NodeTag(dataDir, publicURL, p.internal)
	req.AddCookie(&http.Cookie{Name: "hdtp_csrf_" + tag, Value: "harness-csrf"})
	req.AddCookie(&http.Cookie{Name: "hdtp_session_" + tag, Value: session})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var made struct {
		Secret   string `json:"secret"`
		Endpoint struct {
			ID     string   `json:"id"`
			Events []string `json:"events"`
		} `json:"endpoint"`
	}
	b, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(b, &made); err != nil || res.StatusCode != http.StatusOK || made.Endpoint.ID == "" || !strings.HasPrefix(made.Secret, "whsec_") {
		t.Fatalf("the portal's /webhooks/create answered %d %s", res.StatusCode, b)
	}
	return made.Endpoint.ID, made.Secret
}
