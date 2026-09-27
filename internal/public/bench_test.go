package public

// What one inbound call costs, measured rather than assumed.
//
// Nothing in this repository had a benchmark, so every performance statement
// about it was an opinion. These measure the per-request path a contact
// actually travels: open the envelope, resolve the caller through the pin
// checks, dispatch, seal the answer back. `go test -bench . ./internal/...`
// prints them; the numbers in the commit that added them are the baseline any
// later change is argued against.

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// BenchmarkOpenSealedSmallForm is the common case: a pinned contact naming its
// leaf by fingerprint (PACT §13.2). Every message after the first is this.
func BenchmarkOpenSealedSmallForm(b *testing.B) {
	e := newRecvEnv(b)
	p := newPeer(b, e.nowAt.Add(-time.Hour))
	e.pin(b, p, "active")
	env := e.sealFrom(b, p, "leaf", "send_message", map[string]any{"msg_id": "m", "text": "hello"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.id.OpenSealed(context.Background(), e.acct.ID, TransportFacts{}, env); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpenSealedChainForm carries the chain: first contact, and the first
// envelope after every renewal. It pays for chain validation on top.
func BenchmarkOpenSealedChainForm(b *testing.B) {
	e := newRecvEnv(b)
	p := newPeer(b, e.nowAt.Add(-time.Hour))
	e.pin(b, p, "active")
	env := e.sealFrom(b, p, "chain", "send_message", map[string]any{"msg_id": "m", "text": "hello"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.id.OpenSealed(context.Background(), e.acct.ID, TransportFacts{}, env); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateChain is the certificate work alone: two signature
// verifications and the whole §14.2 profile. It runs on every chain-form
// envelope and on every client certificate the listener sees.
func BenchmarkValidateChain(b *testing.B) {
	p := newPeer(b, time.Now().Add(-time.Hour))
	chain := p.chain()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: now}); !vr.OK {
			b.Fatalf("rule %d", vr.Rule)
		}
	}
}

// BenchmarkSealBack is the answer half: §13.2 requires every sealed request to
// get a sealed result, so this is paid on every call too.
func BenchmarkSealBack(b *testing.B) {
	s := newSealedEnv(b)
	p := newPeer(b, s.nowAt.Add(-time.Hour))
	s.pin(b, p, "active")
	env := s.sealFrom(b, p, "leaf", "send_message", map[string]any{"msg_id": "m", "text": "hello"})
	facts, err := s.id.OpenSealed(context.Background(), s.acct.ID, TransportFacts{}, env)
	if err != nil {
		b.Fatal(err)
	}
	inner := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.deps.sealBack(context.Background(), facts, inner); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSealedCallEndToEnd is the whole wrapper: open, tier, idempotency,
// dispatch, seal back. The one number that answers "what does a message cost".
func BenchmarkSealedCallEndToEnd(b *testing.B) {
	s := newSealedEnv(b)
	p := newPeer(b, s.nowAt.Add(-time.Hour))
	s.pin(b, p, "active")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// A fresh msg_id each time: a replay is answered from the idempotency
		// record, which is a different (and much cheaper) path.
		env := s.sealFrom(b, p, "leaf", "send_message", map[string]any{"msg_id": "m", "text": "hello"},
			func(o *pactidentity.SealOpts) { o.MsgID = "bench-" + strconv.Itoa(i) })
		b.StartTimer()
		res := s.call(b, env, TransportFacts{})
		if res.IsError {
			b.Fatalf("%s", text(b, res))
		}
	}
}
