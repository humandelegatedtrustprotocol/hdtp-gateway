package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The answer to a contact request (contact_accepted, contact_rejected: HDTP §5.1) goes to the asker
// the way the asker's card says — sealed or not (HDTP §3, §13.4) — through the node's one reading of
// a stored contact (node.PeerOf). It was sent sealed to every asker, whatever their card said, so an
// asker whose card says `none` was sent an envelope it had said it would not take.
//
// What is observed is the peer the call is made to, as the outbound budget is asked for it: that is
// the first thing a call does, sealed or not, and the budget here refuses, so nothing is dialled.
// The control is an asker whose card says `required`, who is sealed to.
func TestAnAskerIsAnsweredTheWayItsCardSays(t *testing.T) {
	ctx := context.Background()
	n := newIDNode(t, "node")
	st := openStoreAt(t, n.dir)
	kr := openKeyringAt(t, n.dir)
	acct, err := (&identity.Manager{Store: st, Keyring: kr}).CreateAccount(ctx, "alina", "Alina", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{DataDir: n.dir, PublicURL: "https://node.example", Mode: core.ModeDirect, Seal: core.SealRequired, ClientCert: core.ClientCertPreferred, LANConnections: true}
	nd, err := node.New(ctx, node.Options{Config: cfg, Store: st, Keyring: kr, Landing: landingPage, Limits: limitstest.StartDefault(t).Client})
	if err != nil {
		t.Fatal(err)
	}

	askers := map[string]string{} // fingerprint → the seal its card says
	for _, seal := range []string{"none", "required"} {
		w := testid.NewWallet(t, "Asker "+seal)
		h := w.Issue(t, "https://asker-"+seal+".example/a/x/mcp")
		if _, err := st.InsertContact(ctx, store.Contact{
			AccountID: acct.ID, Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI, Status: "pending_in",
			DisplayName: "Asker " + seal, Card: h.Card("Asker "+seal, seal), Endpoint: h.Endpoint, Leaf: h.LeafDER,
		}); err != nil {
			t.Fatal(err)
		}
		askers[w.Fpr] = seal
	}

	stop := errors.New("the budget refused: nothing is dialled")
	var seen []outbound.Peer
	var tools []string
	ci := newContactInitiator(st, nd, func(string, string, string) {})
	ci.card = func(context.Context, string) (string, error) { return "our card", nil }
	ci.outbound = func(string) (*outbound.Client, error) {
		kp, err := identity.Generate(identity.AlgoEd25519)
		if err != nil {
			return nil, err
		}
		kp.Leaf, kp.Root = []byte("a leaf"), []byte("a root") // a chain to seal under, so a sealed call reaches the budget too
		return &outbound.Client{Keypair: kp, Budget: func(p outbound.Peer, tool string) error {
			seen, tools = append(seen, p), append(tools, tool)
			return stop
		}}, nil
	}
	for fpr, seal := range askers {
		seen, tools = nil, nil
		if err := ci.NotifyApproved(ctx, acct.ID, fpr, nil); !errors.Is(err, stop) {
			t.Fatalf("%s: the call must have reached the budget: %v", seal, err)
		}
		if len(seen) != 1 || seen[0].Root != fpr {
			t.Fatalf("%s: the calls that reached the budget: %+v", seal, seen)
		}
		if seen[0].Seal != seal {
			t.Fatalf("an asker whose card says %q was answered as %q", seal, seen[0].Seal)
		}
		// The tool the budget is asked for: the answer itself, whichever way it travels.
		if tools[0] != "contact_accepted" {
			t.Fatalf("%s: the budget was asked for %q", seal, tools[0])
		}
	}
}
