package public

// The guest total at the sealed_call wrapper (the owner's decision of 2026-09-29,
// docs/release/two-layer-limits-2026-09-28.md §6): the check BEFORE the open runs first and, when it
// refuses, nothing is read and nothing opened; after the open, a call that proved nobody is charged
// in a way that spends the total. What each charge spends is the node's (node.chargeOf, held by
// TestASealedContactIsNotBudgetedAsAGuest); the sidecar's arithmetic is internal/limits'.

import (
	"context"
	"strings"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// guestTotalEnv is a sealed env whose key loader counts its calls, and whose budgets record what
// they were asked.
type guestTotalEnv struct {
	*sealedEnv
	reads    int
	preOpens int
	charged  []Charge
	refuse   bool
	rows     []string
}

func newGuestTotalEnv(t *testing.T) *guestTotalEnv {
	g := &guestTotalEnv{sealedEnv: newSealedEnv(t)}
	load := g.id.RecipientState
	g.id.RecipientState = func(ctx context.Context) (*RecipientState, error) {
		g.reads++
		return load(ctx)
	}
	g.pool.PreOpen = func(context.Context) *Refusal {
		g.preOpens++
		if g.refuse {
			return &Refusal{RetryAfter: 412 * time.Second}
		}
		return nil
	}
	g.pool.Limit = func(_ context.Context, as Charge) *Refusal {
		g.charged = append(g.charged, as)
		return nil
	}
	g.deps.Audit = func(action, resource, outcome string) { g.rows = append(g.rows, action+" "+resource+" "+outcome) }
	return g
}

func TestACallTheTotalRefusesBeforeTheOpenReadsNoKeyAndOpensNothing(t *testing.T) {
	g := newGuestTotalEnv(t)
	stranger := newPeer(t, g.nowAt.Add(-time.Hour))
	g.refuse = true
	res := g.call(t, g.sealFrom(t, stranger, "chain", "request_contact", map[string]any{"card": cardOf(stranger)}), TransportFacts{RemoteIP: "203.0.113.9"})
	if !res.IsError || text(t, res) != `{"code":"rate_limited","retry_after":412}` {
		t.Fatalf("refused before the open: %s, want rate_limited in the clear with the total's wait", text(t, res))
	}
	if g.reads != 0 || len(g.charged) != 0 {
		t.Fatalf("a call refused before the open read the account's keys %d times and was charged %v", g.reads, g.charged)
	}
	if len(g.rows) != 1 || !strings.HasSuffix(g.rows[0], " rate_limited") {
		t.Fatalf("the refusal was not audited once: %v", g.rows)
	}
	// Not even an envelope that does not decode is read past the check.
	g.call(t, &pactidentity.Envelope{}, TransportFacts{})
	if g.reads != 0 {
		t.Fatalf("a malformed call the total refused read a key")
	}
	// The control: with the total holding a call, the same call goes on to the open and is served.
	g.refuse = false
	res = g.call(t, g.sealFrom(t, stranger, "chain", "request_contact", map[string]any{"card": cardOf(stranger)}), TransportFacts{RemoteIP: "203.0.113.9"})
	if g.reads == 0 || len(g.charged) != 1 || g.charged[0] != ChargeCaller {
		t.Fatalf("admitted: %d key reads, charged %v; want the open and the caller's charge", g.reads, g.charged)
	}
	if res.IsError {
		t.Fatalf("admitted, the call was refused: %s", text(t, res))
	}
	if g.preOpens != 3 {
		t.Fatalf("the check ran %d times for three sealed calls", g.preOpens)
	}
}

func TestAnOpenedCallThatProvesNobodyIsChargedTheTotal(t *testing.T) {
	g := newGuestTotalEnv(t)
	contact := newPeer(t, g.nowAt.Add(-time.Hour))
	g.pin(t, contact, "active")
	nobody := newPeer(t, g.nowAt.Add(-time.Hour))

	// A small form naming a leaf nobody pinned: opened, then chain_required, charged as the source
	// alone (with the total, node.chargeOf).
	g.call(t, g.sealFrom(t, nobody, "leaf", "get_card", map[string]any{}), TransportFacts{RemoteIP: "203.0.113.1"})
	// A chain whose signature is not its leaf's: opened, then envelope_invalid.
	other, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	forged := g.sealFrom(t, nobody, "chain", "request_contact", map[string]any{"card": cardOf(nobody)}, func(o *pactidentity.SealOpts) { o.Sender = other })
	if res := g.call(t, forged, TransportFacts{RemoteIP: "203.0.113.2"}); !strings.Contains(text(t, res), "envelope_invalid") {
		t.Fatalf("a chain signed by another key: %s", text(t, res))
	}
	// A client certificate that is not the envelope's leaf: opened, then envelope_invalid.
	mismatch := TransportFacts{RemoteIP: "203.0.113.3", ClientCertSPKI: []byte("not the leaf's key"), ClientCertFingerprint: "sha256:x"}
	if res := g.call(t, g.sealFrom(t, contact, "chain", "send_message", map[string]any{"text": "hi"}), mismatch); !strings.Contains(text(t, res), "envelope_invalid") {
		t.Fatalf("a transport key that is not the envelope's: %s", text(t, res))
	}
	want := []Charge{ChargeSource, ChargeOpened, ChargeOpened}
	if len(g.charged) != len(want) {
		t.Fatalf("charged %v, want %v", g.charged, want)
	}
	for i := range want {
		if g.charged[i] != want[i] {
			t.Fatalf("charged %v, want %v", g.charged, want)
		}
	}
	// Not opened: sealed to a key this account does not hold. Nothing opened, nothing spent.
	g.charged = nil
	unknownKid := g.sealFrom(t, nobody, "chain", "request_contact", map[string]any{"card": cardOf(nobody)}, func(o *pactidentity.SealOpts) {
		k, err := pactidentity.GenerateKey("ed25519")
		if err != nil {
			t.Fatal(err)
		}
		o.RecipientKey = k.Public()
	})
	if res := g.call(t, unknownKid, TransportFacts{RemoteIP: "203.0.113.4"}); !strings.Contains(text(t, res), "envelope_invalid") {
		t.Fatalf("sealed to a key nobody here holds: %s", text(t, res))
	}
	if len(g.charged) != 0 {
		t.Fatalf("an envelope this account cannot open was charged %v", g.charged)
	}
	// The control: the contact's call is charged as the caller, once.
	g.call(t, g.sealFrom(t, contact, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{RemoteIP: "198.51.100.1"})
	if len(g.charged) != 1 || g.charged[0] != ChargeCaller {
		t.Fatalf("the contact's call was charged %v", g.charged)
	}
}
