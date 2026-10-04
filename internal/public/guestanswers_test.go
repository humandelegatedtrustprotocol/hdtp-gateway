package public

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// HDTP §5: a caller this account holds a row for, reaching a guest tool, hears exactly what a
// stranger hears. A blocked one always did. An active or pending_out contact reaches the guest
// tier only demoted — the leaf that signed is older than the one held (HDTP §14.3) — and
// `request_contact` answered it `bad_request` "already known", which tells it that it is known.
// The cloud answers `{"status":"pending"}` and writes nothing (batondeck src/identity/tools.ts).
func TestADemotedContactAskingHearsWhatAStrangerHears(t *testing.T) {
	ctx := context.Background()
	for _, status := range []string{"active", "pending_out", "blocked"} {
		t.Run(status, func(t *testing.T) {
			e := newToolEnv(t)
			card, _, h := testid.Card(t, "Known", "https://known.example/a/k/mcp", "")
			if _, err := e.st.InsertContact(ctx, store.Contact{
				AccountID: e.acct.ID, Fingerprint: h.RootFpr, SPKI: h.Key.Public().SPKI, Status: status,
				Endpoint: h.Endpoint, Leaf: h.LeafDER, Card: card, Permissions: []string{"message.text"}, PinnedAt: 1,
			}); err != nil {
				t.Fatal(err)
			}
			strCard, _, strHost := testid.Card(t, "Stranger", "https://stranger.example/a/s/mcp", "")
			known, _ := e.callAs(h, "", "request_contact", map[string]any{"card": card, "note": "hi"}, nil)
			stranger, _ := e.callAs(strHost, "", "request_contact", map[string]any{"card": strCard, "note": "hi"}, nil)
			if stranger.IsError || known.IsError || body(t, known) != body(t, stranger) {
				t.Fatalf("the %s caller heard %s; a stranger heard %s", status, body(t, known), body(t, stranger))
			}
			c, err := e.st.GetContact(ctx, e.acct.ID, h.RootFpr)
			if err != nil || c.Status != status || len(c.Permissions) != 1 {
				t.Fatalf("the %s row was changed: %+v %v", status, c, err)
			}
			if !slices.Contains(e.rows, "request_contact caller:"+h.RootFpr+" blocked_silent") {
				t.Fatalf("no audit row says the answer was silent: %v", e.rows)
			}
		})
	}
}

// callPlain dispatches a call proven by a client certificate alone (the plaintext path): no
// envelope, the chain from the TLS handshake.
func (e *toolEnv) callPlain(h *testid.Host, tool string, args map[string]any) *mcp.CallToolResult {
	e.t.Helper()
	ctx := WithFacts(context.Background(), TransportFacts{
		ClientCertFingerprint: h.RootFpr, ClientCertSPKI: h.Key.Public().SPKI,
		ClientLeaf: h.LeafDER, ClientEndpoint: h.Endpoint, ClientRoot: h.Chain[1],
	})
	params, err := json.Marshal(map[string]any{"name": tool, "arguments": args})
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := e.pool.Dispatch(ctx, e.acct.ID, h.RootFpr, Payload{Method: "tools/call", Params: params})
	if err != nil {
		e.t.Fatal(err)
	}
	var res mcp.CallToolResult
	if err := json.Unmarshal(raw, &res); err != nil {
		e.t.Fatal(err)
	}
	return &res
}

// HDTP §5, §13.2: a plaintext guest card must name the root the client certificate's chain proved
// and carry the leaf that chain presented. A card that names another root, or the same root's
// other leaf, is answered `identity_required` — the call proved one identity and the card speaks
// for another — at both guest tools, and nothing is written. The control (the card that IS the
// proof) gets through.
func TestAPlaintextGuestCardThatIsNotTheProofIsIdentityRequired(t *testing.T) {
	ctx := context.Background()
	for _, tool := range []string{"request_contact", "redeem_invite"} {
		t.Run(tool, func(t *testing.T) {
			e := newToolEnv(t)
			w := testid.NewWallet(t, "Prover")
			h := w.Issue(t, "https://prover.example/a/p/mcp")
			sibling := w.Issue(t, "https://prover.example/a/p/mcp") // the same root's other leaf
			_, _, other := testid.Card(t, "Other", "https://other.example/a/o/mcp", "")
			args := func(card string) map[string]any {
				a := map[string]any{"card": card}
				if tool == "redeem_invite" {
					tok, _, err := (&contacts.Manager{Store: e.st}).CreateInvite(ctx, e.acct.ID, contacts.InviteOptions{MaxUses: 1})
					if err != nil {
						t.Fatal(err)
					}
					a["token"] = tok
				}
				return a
			}
			for name, card := range map[string]string{
				"another root's card":                             other.Card("Other", ""),
				"the same root, a leaf the chain did not present": sibling.Card("Prover", ""),
			} {
				res := e.callPlain(h, tool, args(card))
				if !res.IsError || !strings.Contains(body(t, res), "identity_required") {
					t.Fatalf("%s: %s", name, body(t, res))
				}
				if _, err := e.st.GetContact(ctx, e.acct.ID, h.RootFpr); err == nil {
					t.Fatalf("%s: a row was written", name)
				}
			}
			if res := e.callPlain(h, tool, args(h.Card("Prover", ""))); res.IsError {
				t.Fatalf("the control, the card that is the proof, was refused: %s", body(t, res))
			}
			if _, err := e.st.GetContact(ctx, e.acct.ID, h.RootFpr); err != nil {
				t.Fatalf("the control wrote no row: %v", err)
			}
		})
	}
}
