package public

// PACT §13.2: "once a request envelope has been successfully opened, an error
// result MUST be sealed back like any other result — a plaintext error is only
// for an envelope that could not be opened at all, where there is no proven key
// to seal toward."
//
// Two refusals past the open answered in the clear: the §5.3 refusal, and
// `pending_approval` from an address the owner has not approved. Neither is an
// envelope that failed to open — both are decided AFTER the sender's signature
// verified — so both told whatever carried the call something it cannot learn
// any other way: that the recipient PINS this sender. A stranger's envelope
// never produces `pending_approval`. That is the correlation sealing exists to
// deny a carrier (PACT §13.5), and in edge mode the carrier is there by
// construction.

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestARefusalPastTheOpenIsSealed(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	if err := s.st.SetAccountHostPolicy(ctx, s.acct.ID, "ask", true); err != nil {
		t.Fatal(err)
	}

	// The same root, calling from an address the owner has not approved. The
	// envelope opens and the signature verifies: the sender is proven, so the
	// answer has a key to be sealed toward.
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, s.nowAt.Add(-5*time.Minute))

	// `update_contact` from that address answers `{"status":"pending"}` — sealed
	// already, and the control for what follows.
	res := s.call(t, s.seal20(t, moved, "chain", "update_contact", map[string]any{"card": card20(moved)}), TransportFacts{})
	if result, _ := s.opened(t, res, moved, "update_contact"); string(result) == "" {
		t.Fatal("update_contact from a new address must answer, sealed")
	}

	// Every other call from that address is `pending_approval`, and must be
	// sealed too. `opened` fails the test on a plaintext refusal.
	res = s.call(t, s.seal20(t, moved, "chain", "send_message", map[string]any{"text": "hello"}), TransportFacts{})
	_, errObj := s.opened(t, res, moved, "send_message")
	if len(errObj) == 0 {
		t.Fatal("pending_approval must arrive in §13.2's `error` member")
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(errObj, &body); err != nil {
		t.Fatalf("the sealed error is not an error object: %v (%s)", err, errObj)
	}
	if body.Code != "pending_approval" {
		t.Fatalf("sealed error code = %q, want pending_approval", body.Code)
	}

	// The third path out of the same place: the guest budget. It is charged
	// before the refusal is written, and its answer opened in the clear too.
	// A carrier reading `rate_limited` learns the recipient is metering THIS
	// sender, which is the same correlation by another name.
	s.pool.Limit = func(context.Context) (bool, time.Duration) { return false, time.Minute }
	res = s.call(t, s.seal20(t, moved, "chain", "send_message", map[string]any{"text": "again"}), TransportFacts{})
	_, errObj = s.opened(t, res, moved, "send_message")
	if err := json.Unmarshal(errObj, &body); err != nil || body.Code != "rate_limited" {
		t.Fatalf("a budget refusal past the open must be sealed too: %v (%s)", err, errObj)
	}
}
