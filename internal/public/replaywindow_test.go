package public

import (
	"context"
	"strings"
	"testing"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// PACT §13.3: "Idempotency records for seen msg_ids MUST be retained until min(exp, ts + 300 s) —
// the end of the window in which the envelope could be presented again and accepted. Nothing later
// than ts + 300 s passes the skew check, so a record held past that point protects nothing, and
// exp − ts may be thirty days: bounding retention by exp alone would let a sender choose how long
// every receiver must remember it." The node kept every envelope's record until its exp (CW-06 of
// the port-parity audit, 2026-09-29).
//
// The store removes a record once its expiry is not after the sweep's clock (DeleteExpiredIdempotency,
// `expires_at <= now`), and the open accepts `now < exp` and `|now − ts| <= 300` in whole seconds —
// so ts + 300 is itself a second at which the envelope is accepted, and exp is not.
//
//   - exp thirty days out: the record goes with the sweep one second after ts + 300. (Red on the node
//     that kept it until exp.)
//   - the boundary: a sweep AT ts + 300 leaves it, and the same envelope presented at ts + 300 is
//     answered from the record, never run again.
//   - exp well inside the window (ts + 60): the record is kept until exp and not a second longer.
func TestAnEnvelopesReplayRecordIsKeptForTheWindowItCanBeAcceptedIn(t *testing.T) {
	ctx := context.Background()
	skew := int64(pactidentity.SkewSeconds)
	setup := func(t *testing.T) (*sealedEnv, *peer, *[]string) {
		s := newSealedEnv(t)
		p := newPeer(t, s.nowAt.Add(-time.Hour))
		s.pin(t, p, "active")
		var ran []string
		s.deps.Audit = func(action, resource, outcome string) {
			if action == "sealed_call" && outcome == "ok" {
				ran = append(ran, resource)
			}
		}
		return s, p, &ran
	}
	send := func(t *testing.T, s *sealedEnv, p *peer, text string, exp time.Time) string {
		t.Helper()
		env := s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": text},
			func(o *pactidentity.SealOpts) { o.Exp = exp.Unix() })
		res := s.call(t, env, TransportFacts{})
		if res.IsError {
			t.Fatalf("the call was refused: %s", text)
		}
		return msgIDFor("send_message", "chain")
	}
	sweep := func(t *testing.T, s *sealedEnv, at int64) int64 {
		t.Helper()
		n, err := s.st.DeleteExpiredIdempotency(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("exp thirty days out", func(t *testing.T) {
		s, p, _ := setup(t)
		ts := s.nowAt.Unix()
		send(t, s, p, "remember me for a month", s.nowAt.Add(30*24*time.Hour))
		if n := sweep(t, s, ts+skew+1); n != 1 {
			t.Fatalf("the sweep one second past ts + %d removed %d records; the envelope can no longer be accepted, so its record protects nothing and must go", skew, n)
		}
	})

	t.Run("the boundary, ts + 300", func(t *testing.T) {
		s, p, ran := setup(t)
		ts := s.nowAt.Unix()
		exp := s.nowAt.Add(30 * 24 * time.Hour)
		env := s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "once"},
			func(o *pactidentity.SealOpts) { o.Exp = exp.Unix() })
		if res := s.call(t, env, TransportFacts{}); res.IsError {
			t.Fatal("the first call was refused")
		}
		if n := sweep(t, s, ts+skew); n != 0 {
			t.Fatalf("a sweep at ts + %d, a second the envelope is still accepted, removed %d records", skew, n)
		}
		s.nowAt = time.Unix(ts+skew, 0).UTC()
		if res := s.call(t, env, TransportFacts{}); res.IsError {
			t.Fatalf("the same envelope at ts + %d must still be accepted: %s", skew, text(t, res))
		}
		if len(*ran) != 1 || !strings.Contains((*ran)[0], p.fpr()) {
			t.Fatalf("the envelope ran %d times; a replay inside its window is answered from its record: %v", len(*ran), *ran)
		}
	})

	t.Run("exp well inside the window", func(t *testing.T) {
		s, p, _ := setup(t)
		ts := s.nowAt.Unix()
		send(t, s, p, "a minute", time.Unix(ts+60, 0))
		if n := sweep(t, s, ts+59); n != 0 {
			t.Fatalf("a sweep at ts + 59, inside exp, removed %d records", n)
		}
		if n := sweep(t, s, ts+60); n != 1 {
			t.Fatalf("a sweep at exp (ts + 60) removed %d records; the envelope is refused from exp on", n)
		}
	})
}
