package public

// Decide is handed the pins a sealed call's proof could concern (pinsFor, store.PinCandidates) and
// no longer every contact. That is only right if it decides exactly as it did with all of them, for
// every way it reads a pin (hdtp-identity envelope.go): the root a chain proves, the address a
// guest's leaf claims (HDTP §5.2), the leaf a small form names, a blocked pin, a root this account
// asked, a leaf nobody holds — and an envelope whose proof cannot be read at all, which is handed no
// pins. Each case decides twice, once with the candidates and once with every contact, and the
// decisions (answer and effects) must be the same; and the candidates must be few, which is the
// point. The cloud holds the same cases (batondeck gateway/test/pin-candidates.test.ts).

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

func candidatesEnv(t *testing.T) (*recvEnv, []*peer) {
	t.Helper()
	e := newRecvEnv(t)
	peers := make([]*peer, 40)
	for i := range peers {
		p := newPeer(t, fixedNow)
		p.leaf = p.leafFor(t, fmt.Sprintf("https://peer-%d.example/mcp", i), fixedNow.Add(-time.Hour))
		status := "active"
		switch i {
		case 3:
			status = "blocked"
		case 4:
			status = "pending_out"
		}
		e.pin(t, p, status)
		peers[i] = p
	}
	return e, peers
}

type decided struct {
	D   hdtpidentity.Decision
	Err string
}

// bothWays decides env with the candidates and with every contact, and says how many pins each had.
func bothWays(t *testing.T, e *recvEnv, env *hdtpidentity.Envelope) (narrow, every decided, narrowPins, everyPins int) {
	t.Helper()
	ctx := context.Background()
	st, err := e.state(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := e.id.nodeState(ctx, e.acct.ID, st, peekProof(e.nowAt, env, st))
	if err != nil {
		t.Fatal(err)
	}
	all, err := e.st.ListContacts(ctx, e.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	full := ns
	full.Pins = pinsOf(all)
	run := func(state hdtpidentity.NodeState) decided {
		d, err := hdtpidentity.Decide(e.nowAt, *env, state)
		out := decided{D: d}
		if err != nil {
			out.Err = err.Error()
		}
		return out
	}
	return run(ns), run(full), len(ns.Pins), len(full.Pins)
}

func TestDecideIsHandedThePinsTheProofConcerns(t *testing.T) {
	e, peers := candidatesEnv(t)
	withCard := func(p *peer) map[string]any { return map[string]any{"card": cardOf(p)} }
	squatter := newPeer(t, fixedNow)
	squatter.leaf = squatter.leafFor(t, "https://peer-7.example/mcp", fixedNow.Add(-time.Hour))
	stranger := newPeer(t, fixedNow)
	stranger.leaf = stranger.leafFor(t, "https://stranger.example/mcp", fixedNow.Add(-time.Hour))
	other := e.sealFrom(t, peers[0], "leaf", "get_card", nil)

	cases := []struct {
		name string
		env  *hdtpidentity.Envelope
	}{
		{"a contact, chain form", e.sealFrom(t, peers[0], "chain", "get_card", nil)},
		{"a contact, small form", e.sealFrom(t, peers[1], "leaf", "get_card", nil)},
		{"a contact's message, small form", e.sealFrom(t, peers[2], "leaf", "send_message", map[string]any{"text": "hi", "msg_id": "m1"})},
		{"a blocked root, chain form", e.sealFrom(t, peers[3], "chain", "get_card", nil)},
		{"a blocked root, small form", e.sealFrom(t, peers[3], "leaf", "get_card", nil)},
		{"a root this account asked, before its answer", e.sealFrom(t, peers[4], "chain", "get_card", nil)},
		{"a stranger, small form: a leaf nobody holds", e.sealFrom(t, stranger, "leaf", "get_card", nil)},
		{"a stranger at a contact's address, claiming it (HDTP §5.2)", e.sealFrom(t, squatter, "chain", "request_contact", withCard(squatter))},
		{"a stranger elsewhere, asking", e.sealFrom(t, stranger, "chain", "request_contact", withCard(stranger))},
		// A proof nobody can read: each is refused whatever the pins, and is now handed none.
		{"a ciphertext that does not open (another envelope's)", func() *hdtpidentity.Envelope {
			env := *e.sealFrom(t, peers[0], "leaf", "get_card", nil)
			env.Ct = other.Ct
			return &env
		}()},
		{"a chain that does not parse", e.sealFrom(t, peers[0], "chain", "get_card", nil, func(o *hdtpidentity.SealOpts) {
			o.SenderChain = [][]byte{{0x30, 0x00}, {0x30, 0x00}}
		})},
		{"sealed to a key this account does not hold", e.sealFrom(t, peers[0], "chain", "get_card", nil, func(o *hdtpidentity.SealOpts) {
			o.RecipientKey = peers[1].host.Public()
		})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			narrow, every, narrowPins, everyPins := bothWays(t, e, c.env)
			if !reflect.DeepEqual(narrow, every) {
				t.Fatalf("decided differently with the candidates:\n  candidates: %+v\n  every:      %+v", narrow, every)
			}
			if everyPins < 40 || narrowPins > 2 {
				t.Fatalf("pins handed over: %d of %d", narrowPins, everyPins)
			}
		})
	}

	t.Run("the address claim is found among the candidates, not by luck", func(t *testing.T) {
		narrow, _, _, _ := bothWays(t, e, e.sealFrom(t, squatter, "chain", "request_contact", withCard(squatter)))
		if claim := narrow.D.Result["address_claim"]; claim != peers[7].fpr() {
			t.Fatalf("address_claim %v, want %s (%+v)", claim, peers[7].fpr(), narrow)
		}
	})
	t.Run("a proof that cannot be read is refused and handed no pins", func(t *testing.T) {
		env := *e.sealFrom(t, peers[2], "chain", "get_card", nil)
		env.Ct = other.Ct
		narrow, _, narrowPins, _ := bothWays(t, e, &env)
		if code, _ := narrow.D.Result["code"].(string); code != "envelope_invalid" || narrowPins != 0 {
			t.Fatalf("code %q with %d pins", code, narrowPins)
		}
	})
}
