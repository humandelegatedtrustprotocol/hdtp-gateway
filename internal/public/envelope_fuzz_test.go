package public

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// FuzzSealedEnvelope feeds arbitrary bytes down the path a sealed_call's argument takes in
// production: decoded into an envelope exactly as the wrapper decodes it (sealed.go), then
// opened by OpenSealed — the suite, the key id, the HPKE open, the chain or leaf, the signature,
// the freshness window and the pin checks, all before anything is dispatched. For a guest every
// byte of it is the attacker's.
//
// It replaces a target that decoded the opened plaintext into the Payload struct with
// encoding/json. Production never does that decode — the library's Decide parses the plaintext
// and the node builds Payload from its result — so that target fuzzed a parser nothing runs.
//
// Two properties hold on every input: the open never panics, and a refusal is always one of the
// PACT §12 codes an envelope can earn — never `unavailable`, which is what Code answers for an
// error it does not recognise. An envelope that does open was sealed by one of the two peers the
// seeds come from — the contact or the stranger: a mutation that still verifies cannot speak for
// anybody else.
func FuzzSealedEnvelope(f *testing.F) {
	e := newRecvEnv(f)
	p := newPeer(f, e.nowAt.Add(-time.Hour))
	e.pin(f, p, "active")
	for _, form := range []string{"chain", "leaf"} {
		b, err := json.Marshal(e.sealFrom(f, p, form, "send_message", map[string]any{"msg_id": "m", "text": "hello"}))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	stranger := newPeer(f, e.nowAt.Add(-time.Hour))
	if b, err := json.Marshal(e.sealFrom(f, stranger, "chain", "request_contact", map[string]any{"card": cardOf(stranger)})); err == nil {
		f.Add(b) // a guest's first envelope: the stranger's path through the open
	}
	for _, s := range []string{`{}`, `null`, `[]`, `{"protected":"","enc":"","ct":"","sig":""}`, `{"protected":"e30","enc":"AA","ct":"AA","sig":"AA"}`} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var env pactidentity.Envelope
		if json.Unmarshal(data, &env) != nil {
			return // the wrapper answers envelope_invalid before OpenSealed is reached
		}
		facts, err := e.id.OpenSealed(context.Background(), e.acct.ID, TransportFacts{}, &env)
		if err != nil {
			if c := Code(err); c == "unavailable" {
				t.Fatalf("an envelope refusal is not a PACT §12 code: %v", err)
			}
			return
		}
		if facts.From != p.fpr() && facts.From != stranger.fpr() {
			t.Fatalf("an envelope opened as %s, a root no seed was sealed by", facts.From)
		}
	})
}
