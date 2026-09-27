package scenario

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// S7 — what happens when the network misbehaves, and what must happen anyway.
func TestResilienceUnderImpairment(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S7", Name: "msg_id idempotency, a real partition and heal, delivery over a lossy link", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 12 * time.Minute,
	})

	p, err := w.Paired(ctx, images.Node)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// PACT §6.2: "a call bearing an already-seen msg_id is acknowledged, not
	// re-executed". This is what makes the retry path safe — and it is the
	// property P12-04 found broken in the store, where an outbound id colliding
	// with an inbound one was silently discarded.
	t.Run("a repeated msg_id is acknowledged, never duplicated", func(t *testing.T) {
		const id = "harness-idem-1"
		args := map[string]any{
			"text": "exactly once " + PlaintextCanary, "sender": "agent", "msg_id": id,
		}
		first, err := p.Contact.Call(ctx, p.Target, "send_message", args, id)
		if err != nil {
			t.Fatalf("first send: %v", err)
		}
		second, err := p.Contact.Call(ctx, p.Target, "send_message", args, id)
		if err != nil {
			t.Fatalf("replaying the same msg_id was REFUSED; it must be acknowledged: %v", err)
		}
		var a, b struct {
			ThreadID string `json:"thread_id"`
		}
		_ = json.Unmarshal([]byte(first), &a)
		_ = json.Unmarshal([]byte(second), &b)
		if a.ThreadID == "" || a.ThreadID != b.ThreadID {
			t.Fatalf("replay produced a different thread (%q vs %q) — it was re-executed", a.ThreadID, b.ThreadID)
		}
		body, err := p.Owner.Call(ctx, "read_thread", map[string]any{
			"account_id": p.AccountID, "thread_id": a.ThreadID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(body, "exactly once"); n != 1 {
			t.Fatalf("the thread holds %d copies of a message sent twice with one msg_id: %s", n, shorten(body, 300))
		}
	})

	// The shaper has to be real, or every resilience claim built on it is
	// decoration. Partition means GONE, not slow.
	t.Run("a partition actually severs the node, and healing restores it", func(t *testing.T) {
		before, err := p.Contact.ListTools(ctx, p.Target)
		if err != nil {
			t.Fatalf("precondition: the node was already unreachable: %v", err)
		}
		if len(before) == 0 {
			t.Fatal("precondition: no tools before partition")
		}

		if err := p.Fab.Partition(ctx, p.Node); err != nil {
			t.Fatalf("applying the partition: %v", err)
		}
		cut, cancelCut := context.WithTimeout(ctx, 15*time.Second)
		_, cutErr := p.Contact.ListTools(cut, p.Target)
		cancelCut()
		if cutErr == nil {
			t.Fatal("the node answered through a 100% loss partition — the shaper is not " +
				"actually impairing anything, so every S7 result would be meaningless")
		}
		t.Logf("partitioned: %v", shorten(cutErr.Error(), 120))

		if err := p.Fab.Heal(ctx, p.Node); err != nil {
			t.Fatalf("healing: %v", err)
		}
		// Poll rather than sleep: the point is that it comes back, not when.
		deadline := time.Now().Add(60 * time.Second)
		for {
			if _, err := p.Contact.ListTools(ctx, p.Target); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the node never recovered after the partition was lifted")
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Log("healed: the node answers again")
	})

	// Latency is the ordinary case, not the dramatic one — and a node that only
	// works on a perfect link is not a node anyone can use.
	t.Run("the node still serves under latency and loss", func(t *testing.T) {
		if err := p.Fab.Shape(ctx, p.Node, fabric.Netem{Latency: "120ms", Jitter: "30ms", Loss: "2%"}); err != nil {
			t.Fatalf("shaping: %v", err)
		}
		defer func() { _ = p.Fab.Heal(context.Background(), p.Node) }()

		const id = "harness-slow-1"
		if _, err := p.Contact.Call(ctx, p.Target, "send_message", map[string]any{
			"text": "over a bad link " + PlaintextCanary, "sender": "agent", "msg_id": id,
		}, id); err != nil {
			t.Fatalf("a message over a 120ms/2%%-loss link failed: %v", err)
		}
		t.Log("delivered over an impaired link")
	})
}
