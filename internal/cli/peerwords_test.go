package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// A peer's refusal of a redemption is repeated by its §12 code and nothing else: a string of the
// protocol's shape that is not a code, or 64 KiB of anything, is "refused". The sentence
// add_contact answers with was built from whatever the peer sent. The control, a real code, is
// repeated.
func TestARedemptionRefusalRepeatsOnlyAProtocolCode(t *testing.T) {
	answer := func(code string) *mcp.CallToolResult {
		b, _ := json.Marshal(map[string]string{"code": code})
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
	}
	for code, want := range map[string]string{
		"invite_invalid":             "invite_invalid",
		"wire_money_to_this_account": "refused",
		strings.Repeat("x", 60000):   "refused",
	} {
		if got := refusalCodeOf(answer(code)); got != want {
			t.Errorf("refusalCodeOf(%.30q) = %.30q, want %q", code, got, want)
		}
	}
}

// add_contact answers a peer it could not reach as unavailable, and a peer that answered with a
// refusal as bad_request naming the §12 code: both were bad_request ("the peer refused ..."), the
// dial included. The control, a request that lands, is no refusal.
func TestAddContactTellsAnUnreachablePeerFromARefusal(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPeer(t, "Chitra", "https://chitra.invalid/mcp")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(offerFor(t, p, "Chitra"))
	}))
	t.Cleanup(srv.Close)
	ours := testid.CardFor(t, "Alina", "https://alina.example/mcp")
	var requestErr error
	ci := &contactInitiator{
		manager:    &contacts.Manager{Store: st, ContactCap: func() int { return 100 }},
		card:       func(context.Context, string) (string, error) { return ours, nil },
		outbound:   func(string) (*outbound.Client, error) { return &outbound.Client{}, nil },
		request:    func(context.Context, string, outbound.Peer, string, string) error { return requestErr },
		audit:      func(string, string, string) {},
		httpClient: srv.Client,
	}
	codeOf := func(err error) (string, string) { return refusal.Of(err) }

	_, err = ci.RedeemInvite(ctx, a.ID, srv.URL+"/i/tok", "")
	if code, detail := codeOf(err); code != "unavailable" || detail != "the peer could not be reached to redeem the invite" {
		t.Errorf("a redemption whose call failed: %v → %s %q", err, code, detail)
	}
	card := testid.CardFor(t, "Dev", "https://dev.example/mcp")
	requestErr = node.ErrNotReached{Err: errors.New("dial tcp: connection refused")}
	_, err = ci.RequestContact(ctx, a.ID, card, "")
	if code, detail := codeOf(err); code != "unavailable" || detail != "the request did not reach the peer" {
		t.Errorf("a request that did not reach: %v → %s %q", err, code, detail)
	}
	requestErr = node.ErrRequestRefused{Code: "permission_denied"}
	_, err = ci.RequestContact(ctx, a.ID, card, "")
	if code, detail := codeOf(err); code != "bad_request" || detail != "the peer refused the request: permission_denied" {
		t.Errorf("a request the peer refused: %v → %s %q", err, code, detail)
	}
	requestErr = nil
	if _, err := ci.RequestContact(ctx, a.ID, testid.CardFor(t, "Eve", "https://eve.example/mcp"), ""); err != nil {
		t.Errorf("the control: %v", err)
	}
}
