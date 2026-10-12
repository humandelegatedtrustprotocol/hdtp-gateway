package outbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/envelope"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Every way a sealed exchange ends on an answer nothing verified is envelope_invalid to whoever
// reads the code (HDTP §12: an envelope that is malformed, mis-signed, or whose chain fails §14.2),
// whatever the one follow-up got back: the owner MCP's call_contact answers errors.Is
// envelope.ErrInvalid so. A peer that cannot be dialled is not; and the control, a
// certificate_renewed whose chain is the peer's own, is followed and delivers.
func TestAnExchangeThatEndsUnverifiedIsEnvelopeInvalid(t *testing.T) {
	retire := func(p *renewedPeer) {
		p.state.Former = append(p.state.Former, p.state.Keys[0].Kid)
		p.state.Keys = p.state.Keys[1:]
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, alina *testIdentity, p *renewedPeer)
		calls map[string]int
	}{
		{"a sealed get_card answered by the record", func(t *testing.T, _ *testIdentity, p *renewedPeer) {
			p.cardForm = "leaf"
		}, map[string]int{"sealed send_message": 1, "sealed get_card": 1}},
		{"a sealed get_card answered certificate_renewed", func(t *testing.T, _ *testIdentity, p *renewedPeer) {
			p.retireAfter = "send_message"
		}, map[string]int{"sealed send_message": 1, "certificate_renewed": 1}},
		{"a sealed get_card answered under another root's chain", func(t *testing.T, alina *testIdentity, p *renewedPeer) {
			other := newTestIdentity(t, "Alina", alina.endpoint)
			leaf, key := forgedLeaf(t, other.root, "Alina", alina.endpoint, time.Now().Add(-10*time.Minute))
			p.cardSigner, p.cardChain = key, [][]byte{leaf, other.rootCert}
		}, map[string]int{"sealed send_message": 1, "sealed get_card": 1}},
		{"a sealed get_card whose answer is not an envelope", func(t *testing.T, _ *testIdentity, p *renewedPeer) {
			p.mangleTool = "get_card"
			p.mangle = func(s string) string { return strings.Replace(s, `{`, `{"note":"x",`, 1) }
		}, map[string]int{"sealed send_message": 1, "sealed get_card": 1}},
		{"the retry after the get_card answered under a leaf nobody pinned", func(t *testing.T, alina *testIdentity, p *renewedPeer) {
			leaf, key := forgedLeaf(t, alina.root, "Alina", alina.endpoint, time.Now().Add(-5*time.Minute))
			p.retrySigner, p.retryChain = key, [][]byte{leaf, alina.rootCert}
		}, map[string]int{"sealed send_message": 2, "sealed get_card": 1}},
		{"a certificate_renewed carrying another root's chain", func(t *testing.T, alina *testIdentity, p *renewedPeer) {
			retire(p)
			other := newTestIdentity(t, "Alina", alina.endpoint)
			leaf, _ := forgedLeaf(t, other.root, "Alina", alina.endpoint, time.Now().Add(-10*time.Minute))
			p.renewedData = map[string]any{"chain": []string{hdtpidentity.B64url(leaf), hdtpidentity.B64url(other.rootCert)}}
		}, map[string]int{"certificate_renewed": 1, "sealed send_message": 0}},
		{"a certificate_renewed whose chain is not base64url", func(t *testing.T, _ *testIdentity, p *renewedPeer) {
			retire(p)
			p.renewedData = map[string]any{"chain": []string{"!!", "!!"}}
		}, map[string]int{"certificate_renewed": 1, "sealed send_message": 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
			bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
			p := startRenewedPeer(t, alina, bharat)
			tc.setup(t, alina, p)
			var repinned [][]byte
			_, err := callerTo(t, bharat, p, &repinned).SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-codes")
			if !errors.Is(err, envelope.ErrInvalid) {
				t.Fatalf("answered %v, want an error that is envelope.ErrInvalid", err)
			}
			for k, want := range tc.calls {
				if p.calls[k] != want {
					t.Fatalf("calls %v, want %s = %d: the case did not reach the step it is about", p.calls, k, want)
				}
			}
		})
	}

	t.Run("a peer that cannot be dialled", func(t *testing.T) {
		alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
		bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
		p := startRenewedPeer(t, alina, bharat)
		c := bharat.client()
		c.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
		_, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-down")
		if err == nil || errors.Is(err, envelope.ErrInvalid) {
			t.Fatalf("answered %v, want a failure that is not envelope_invalid", err)
		}
	})

	t.Run("the control: a certificate_renewed carrying the peer's own chain", func(t *testing.T) {
		alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
		bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
		p := startRenewedPeer(t, alina, bharat)
		retire(p)
		var repinned [][]byte
		res, err := callerTo(t, bharat, p, &repinned).SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-control")
		if err != nil {
			t.Fatalf("the control must follow the renewal and deliver: %v", err)
		}
		delivered(t, res)
	})
}
