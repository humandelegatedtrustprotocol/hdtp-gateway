package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

type auditRow struct{ action, resource, outcome string }

// addContactRig is one account, an invite landing serving Chitra's offer, and an initiator whose
// outbound client and request_contact the test chooses; every audit row it writes is kept.
type addContactRig struct {
	ctx     context.Context
	st      store.Store
	account string
	peer    *testPeer
	landing *httptest.Server
	ci      *contactInitiator
	rows    []auditRow
}

func newAddContactRig(t *testing.T, client func(string) (*outbound.Client, error),
	request func(context.Context, string, outbound.Peer, string, string) error) *addContactRig {
	t.Helper()
	r := &addContactRig{ctx: context.Background()}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(r.ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(r.ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	r.st, r.account = st, a.ID
	r.peer = newTestPeer(t, "Chitra", "https://chitra.invalid/mcp")
	r.landing = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(offerFor(t, r.peer, "Chitra"))
	}))
	t.Cleanup(r.landing.Close)
	ours := testid.CardFor(t, "Alina", "https://alina.example/mcp")
	r.ci = &contactInitiator{
		manager:    &contacts.Manager{Store: st, ContactCap: func() int { return 100 }},
		card:       func(context.Context, string) (string, error) { return ours, nil },
		outbound:   client,
		request:    request,
		audit:      func(action, resource, outcome string) { r.rows = append(r.rows, auditRow{action, resource, outcome}) },
		httpClient: r.landing.Client,
	}
	return r
}

func (r *addContactRig) initiated() []auditRow {
	var out []auditRow
	for _, row := range r.rows {
		if row.action == "contact_initiate" {
			out = append(out, row)
		}
	}
	return out
}

// An invite link that does not answer is audited with what failed, so the owner and the operator
// can tell a tunnel's edge closing the connection from a link that is gone; the bearer token in the
// link is in neither that row nor the error. The fetch left no row at all, and the error's text
// carried the whole link. The refusal on the owner's doors is the sentence it was.
func TestAnInviteLinkThatDoesNotAnswerIsAuditedWithItsCauseAndNotItsToken(t *testing.T) {
	const token = "f2529789682e342b080e8b3d07a38d9c"
	r := newAddContactRig(t, func(string) (*outbound.Client, error) {
		t.Fatal("a link that never answered was followed by a call to the peer")
		return nil, nil
	}, nil)
	down := httptest.NewTLSServer(http.NotFoundHandler())
	link := down.URL + "/i/" + token
	down.Close()

	_, err := r.ci.RedeemInvite(r.ctx, r.account, link, "")
	if code, detail := refusal.Of(err); code != "unavailable" || detail != "could not reach the invite link" {
		t.Fatalf("a link that does not answer: %s %q (%v)", code, detail, err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the error carries the invite's token: %v", err)
	}
	rows := r.initiated()
	if len(rows) != 1 || rows[0].outcome != "unreachable" {
		t.Fatalf("contact_initiate rows %+v, want one, unreachable", rows)
	}
	if !strings.Contains(rows[0].resource, " why:") || !strings.Contains(rows[0].resource, "127.0.0.1") {
		t.Errorf("the row does not say what failed: %q", rows[0].resource)
	}
	if strings.Contains(rows[0].resource, token) {
		t.Errorf("the row carries the invite's token: %q", rows[0].resource)
	}
}

// This node's own outbound budget refusing the call is told as rate_limited with the wait, on both
// of add_contact's paths, and audited as such. It was told as a peer that could not be reached,
// audited unreachable, and the wait was lost. The control, a dial that fails, is still unavailable.
func TestThisNodesOwnBudgetIsToldAsRateLimited(t *testing.T) {
	limited := &outbound.RateLimited{RetryAfter: 6500 * time.Millisecond}
	var requestErr error
	r := newAddContactRig(t,
		func(string) (*outbound.Client, error) {
			return &outbound.Client{Budget: func(outbound.Peer, string) error { return limited }}, nil
		},
		func(context.Context, string, outbound.Peer, string, string) error { return requestErr })

	_, err := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if code, detail := refusal.Of(err); code != "rate_limited" || !strings.Contains(detail, "try again in 7 s") {
		t.Errorf("a redemption this node's budget refused: %s %q (%v)", code, detail, err)
	}
	card := testid.CardFor(t, "Dev", "https://dev.example/mcp")
	requestErr = fmt.Errorf("request_contact: %w", limited)
	_, err = r.ci.RequestContact(r.ctx, r.account, card, "")
	if code, detail := refusal.Of(err); code != "rate_limited" || !strings.Contains(detail, "try again in 7 s") {
		t.Errorf("a request this node's budget refused: %s %q (%v)", code, detail, err)
	}
	if rows := r.initiated(); len(rows) != 2 || rows[0].outcome != "rate_limited" || rows[1].outcome != "rate_limited" {
		t.Errorf("contact_initiate rows %+v, want two, rate_limited", rows)
	}
	requestErr = fmt.Errorf("request_contact: dial tcp: connection refused")
	_, err = r.ci.RequestContact(r.ctx, r.account, card, "")
	if code, _ := refusal.Of(err); code != "unavailable" {
		t.Errorf("the control, a dial that failed: %s (%v)", code, err)
	}
}

// A peer that answers rate_limited is told as rate_limited, not as a bad request: it clears with
// time, and nothing about the owner's request was wrong. The control, another code, is still
// bad_request.
func TestAPeersRateLimitIsToldAsRateLimited(t *testing.T) {
	var requestErr error
	r := newAddContactRig(t, nil,
		func(context.Context, string, outbound.Peer, string, string) error { return requestErr })
	card := testid.CardFor(t, "Dev", "https://dev.example/mcp")

	requestErr = node.ErrRequestRefused{Code: "rate_limited"}
	_, err := r.ci.RequestContact(r.ctx, r.account, card, "")
	if code, detail := refusal.Of(err); code != "rate_limited" || !strings.Contains(detail, "rate_limited") {
		t.Errorf("a peer's rate_limited: %s %q (%v)", code, detail, err)
	}
	requestErr = node.ErrRequestRefused{Code: "permission_denied"}
	_, err = r.ci.RequestContact(r.ctx, r.account, card, "")
	if code, _ := refusal.Of(err); code != "bad_request" {
		t.Errorf("the control, permission_denied: %s (%v)", code, err)
	}
}

// Redeeming the link of somebody this account already holds active is answered from the row:
// nothing is dialled, nothing spent, and the answer is the contact that exists — as the cloud
// answers it. The node called the inviter, which refuses an active contact's redeem_invite
// (permission_denied, HDTP §6.2), and the owner was told bad_request.
func TestAnActiveContactsInviteIsAnsweredFromTheRow(t *testing.T) {
	r := newAddContactRig(t, func(string) (*outbound.Client, error) {
		t.Fatal("the invite of a contact already active was redeemed by calling them")
		return nil, nil
	}, nil)
	if _, err := r.st.InsertContact(r.ctx, store.Contact{AccountID: r.account, Fingerprint: r.peer.Root(),
		Status: "active", DisplayName: "Chitra"}); err != nil {
		t.Fatal(err)
	}
	got, err := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if err != nil || got.Status != "active" || got.Fingerprint != r.peer.Root() || got.DisplayName != "Chitra" {
		t.Fatalf("an active contact's invite: %+v, %v", got, err)
	}
	if rows := r.initiated(); len(rows) != 1 || rows[0].outcome != "active" {
		t.Errorf("contact_initiate rows %+v, want one, active", rows)
	}
}

// A link that cannot even be made into a request (a control character after the token) is refused
// without its token too: that error is a *url.Error as well, and its text was the whole link.
func TestALinkThatIsNotARequestIsRefusedWithoutItsToken(t *testing.T) {
	const token = "f2529789682e342b080e8b3d07a38d9c"
	_, err := fetchOffer(context.Background(), http.DefaultClient, "https://peer.example/i/"+token+"\n")
	if err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("the error carries the invite's token: %v", err)
	}
}

// A peer that answers a redemption rate_limited is told as rate_limited on this path too: the
// peer is real, serving redeem_invite under Chitra's chain, and the call reaches it. It was
// bad_request ("the peer refused the redemption: rate_limited"). The control, the same peer
// answering invite_invalid, is still bad_request.
func TestAPeersRateLimitOnARedemptionIsToldAsRateLimited(t *testing.T) {
	answer := `{"code":"rate_limited","retry_after":5}`
	r := newRedeemingPeerRig(t, func() *mcp.CallToolResult {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: answer}}}
	})

	_, err := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if code, detail := refusal.Of(err); code != "rate_limited" || detail != "the peer refused the redemption: rate_limited; try again later" {
		t.Errorf("a peer's rate_limited on a redemption: %s %q (%v)", code, detail, err)
	}
	answer = `{"code":"invite_invalid"}`
	_, err = r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if code, _ := refusal.Of(err); code != "bad_request" {
		t.Errorf("the control, invite_invalid: %s (%v)", code, err)
	}
	if rows := r.initiated(); len(rows) != 2 || rows[0].outcome != "refused" || rows[1].outcome != "refused" {
		t.Errorf("contact_initiate rows %+v, want two, refused", rows)
	}
}

// A link pasted with a space before it and a newline after it is the link: the offer is fetched
// and verified, and the answer is about the peer (here, one that cannot be dialled), never internal.
// The split trimmed the link and the fetch was given it raw, so the request could not be built and
// the owner was told internal. The control, the clean link, is answered the same.
func TestAPastedLinkIsFetchedTrimmed(t *testing.T) {
	r := newAddContactRig(t, func(string) (*outbound.Client, error) { return &outbound.Client{}, nil }, nil)
	for _, link := range []string{" " + r.landing.URL + "/i/tok\n", r.landing.URL + "/i/tok"} {
		_, err := r.ci.RedeemInvite(r.ctx, r.account, link, "")
		if code, detail := refusal.Of(err); code != "unavailable" || detail != "the peer could not be reached to redeem the invite" {
			t.Errorf("link %q: %s %q (%v)", link, code, detail, err)
		}
	}
}

// This node's limits sidecar not answering is told as that, on both of add_contact's paths, and
// audited limits_unavailable: nothing left the host, and the peer was never tried. It was told as a
// peer that could not be reached and audited unreachable.
func TestASidecarThatIsDownIsToldAsThat(t *testing.T) {
	r := newAddContactRig(t,
		func(string) (*outbound.Client, error) {
			return &outbound.Client{Budget: func(outbound.Peer, string) error { return outbound.ErrLimitsUnavailable }}, nil
		},
		func(context.Context, string, outbound.Peer, string, string) error {
			return fmt.Errorf("request_contact: %w", outbound.ErrLimitsUnavailable)
		})

	_, redeemErr := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	_, requestErr := r.ci.RequestContact(r.ctx, r.account, testid.CardFor(t, "Dev", "https://dev.example/mcp"), "")
	for _, err := range []error{redeemErr, requestErr} {
		if code, detail := refusal.Of(err); code != "unavailable" || detail != outbound.LimitsUnavailableSentence {
			t.Errorf("with the sidecar down: %s %q (%v)", code, detail, err)
		}
	}
	if rows := r.initiated(); len(rows) != 2 || rows[0].outcome != "limits_unavailable" || rows[1].outcome != "limits_unavailable" {
		t.Errorf("contact_initiate rows %+v, want two, limits_unavailable", rows)
	}
}

// newRedeemingPeerRig is the rig with Chitra real: an MCP server under her chain, at the address
// her leaf names, whose redeem_invite answers what answer returns; redeemed counts its calls.
func newRedeemingPeerRig(t *testing.T, answer func() *mcp.CallToolResult) *redeemingPeerRig {
	t.Helper()
	rp := &redeemingPeerRig{}
	var peerAddr string
	rp.addContactRig = newAddContactRig(t, func(string) (*outbound.Client, error) {
		return &outbound.Client{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "chitra.invalid:443" {
				addr = peerAddr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}, nil
	}, nil)
	srv := mcp.NewServer(&mcp.Implementation{Name: "chitra", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "redeem_invite", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest, map[string]any) (*mcp.CallToolResult, any, error) {
			rp.redeemed++
			return answer(), nil, nil
		})
	peer := httptest.NewUnstartedServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	peer.TLS = &tls.Config{Certificates: []tls.Certificate{rp.peer.Cert}}
	peer.StartTLS()
	t.Cleanup(peer.Close)
	peerAddr = peer.Listener.Addr().String()
	return rp
}

type redeemingPeerRig struct {
	*addContactRig
	redeemed int
}

// Redeeming the invite of somebody this account holds pending_out — it asked them by card and they
// have not answered — moves that row on: they accept the redemption, the row is active, and the
// owner is told active. It was refused bad_request ("already a contact or already pending") after
// their node had spent the invite and made us active there, so the two sides disagreed.
func TestARedemptionOverAPendingRequestMakesTheContactActive(t *testing.T) {
	r := newRedeemingPeerRig(t, func() *mcp.CallToolResult {
		return &mcp.CallToolResult{StructuredContent: map[string]any{"status": "accepted", "permissions": []string{"message.text"}}}
	})
	if err := r.ci.manager.InitiatedByFingerprint(r.ctx, r.account, r.peer.Root(), r.peer.Card("Chitra")); err != nil {
		t.Fatal(err)
	}
	got, err := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if err != nil || got.Status != "active" {
		t.Fatalf("a redemption over pending_out: %+v, %v", got, err)
	}
	rows, err := r.st.ListContacts(r.ctx, r.account)
	if err != nil || len(rows) != 1 || rows[0].Status != "active" {
		t.Errorf("contacts %+v (%v), want one, active", rows, err)
	}
	if rows := r.initiated(); len(rows) != 1 || rows[0].outcome != "active" {
		t.Errorf("contact_initiate rows %+v, want one, active", rows)
	}
	if r.redeemed != 1 {
		t.Errorf("redeem_invite called %d times, want once", r.redeemed)
	}
}

// Redeeming the invite of somebody this account has blocked is refused before anything is dialled
// or spent, as the cloud refuses it: unblocking is the owner's decision, and an invite is not a way
// around it. It was dialled, and their invite spent.
func TestABlockedIdentitysInviteIsRefusedBeforeTheDial(t *testing.T) {
	r := newAddContactRig(t, func(string) (*outbound.Client, error) {
		t.Fatal("the invite of a blocked identity was redeemed by calling them")
		return nil, nil
	}, nil)
	if _, err := r.st.InsertContact(r.ctx, store.Contact{AccountID: r.account, Fingerprint: r.peer.Root(),
		Status: "blocked", DisplayName: "Chitra"}); err != nil {
		t.Fatal(err)
	}
	_, err := r.ci.RedeemInvite(r.ctx, r.account, r.landing.URL+"/i/tok", "")
	if code, detail := refusal.Of(err); code != "bad_request" || !strings.Contains(detail, "unblock them first") {
		t.Errorf("a blocked identity's invite: %s %q (%v)", code, detail, err)
	}
	if rows := r.initiated(); len(rows) != 1 || rows[0].outcome != "blocked" {
		t.Errorf("contact_initiate rows %+v, want one, blocked", rows)
	}
}
