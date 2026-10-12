package public

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
)

// refusalCase is one case of the cloud's go-refusals.json: where the refusal travels and its body,
// whole or by shape, or `refused: false` for the control.
type refusalCase struct {
	Name    string         `json:"name"`
	Where   string         `json:"where"`
	Body    map[string]any `json:"body"`
	Shape   map[string]any `json:"shape"`
	Refused *bool          `json:"refused"`
}

// refusalShape is a body with `code` kept and every other value replaced by its JSON type, so a
// `retry_after` or a chain that differs by run is compared by what it is.
func refusalShape(body map[string]any) map[string]any {
	var shape func(v any) any
	shape = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, e := range x {
				out[k] = shape(e)
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, e := range x {
				out[i] = shape(e)
			}
			return out
		case string:
			return "string"
		case float64:
			if x == float64(int64(x)) {
				return "integer"
			}
			return "number"
		case bool:
			return "boolean"
		}
		return "null"
	}
	out := shape(body).(map[string]any)
	if code, ok := body["code"]; ok {
		out["code"] = code
	}
	return out
}

// servedRefusal is what this node answers one case with: where it travelled, and the body, or nil
// for an answer that was not refused.
type servedRefusal struct {
	where string
	body  map[string]any
}

// served is each case of the fixture driven through the node's sealed_call (sealedHandler, as the
// public surface serves it), by name.
func servedRefusals(t *testing.T) map[string]func(t *testing.T) servedRefusal {
	decode := func(t *testing.T, raw string) map[string]any {
		t.Helper()
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatalf("a refusal that is not a JSON object: %v (%s)", err, raw)
		}
		return body
	}
	// sealed reads an opened answer: its error member, or the tool error inside its result.
	sealed := func(t *testing.T, s *sealedEnv, res *mcp.CallToolResult, p *peer, msgID string) servedRefusal {
		t.Helper()
		result, errObj := s.openedWith(t, res, p, msgID)
		if len(errObj) > 0 {
			return servedRefusal{"sealed error", decode(t, string(errObj))}
		}
		var inner struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(result, &inner); err != nil || len(inner.Content) == 0 {
			t.Fatalf("the sealed result is not a CallToolResult: %v (%s)", err, result)
		}
		if !inner.IsError {
			return servedRefusal{"sealed result", nil}
		}
		return servedRefusal{"sealed result", decode(t, inner.Content[0].Text)}
	}
	clear := func(t *testing.T, res *mcp.CallToolResult) servedRefusal {
		t.Helper()
		if !res.IsError {
			t.Fatalf("answered sealed where a refusal in the clear was expected: %s", text(t, res))
		}
		return servedRefusal{"clear", decode(t, text(t, res))}
	}
	contactCall := func(t *testing.T, tool string, limit func(context.Context, Charge) *Refusal) servedRefusal {
		s := newSealedEnv(t)
		s.pool.Limit = limit
		p := newPeer(t, s.nowAt.Add(-time.Hour))
		s.pin(t, p, "active")
		res := s.call(t, s.sealFrom(t, p, "chain", tool, map[string]any{"text": "parity"}), TransportFacts{})
		return sealed(t, s, res, p, msgIDFor(tool, "chain"))
	}
	return map[string]func(t *testing.T) servedRefusal{
		"a contact calls a tool its grants leave out": func(t *testing.T) servedRefusal {
			return contactCall(t, "book_slot", nil)
		},
		"a contact calls a tool that does not exist": func(t *testing.T) servedRefusal {
			return contactCall(t, "no_such_tool", nil)
		},
		"a contact calls past its budget": func(t *testing.T) servedRefusal {
			return contactCall(t, "send_message", func(context.Context, Charge) *Refusal { return &Refusal{RetryAfter: time.Minute} })
		},
		"a pending_out root calls send_message": func(t *testing.T) servedRefusal {
			s := newSealedEnv(t)
			p := newPeer(t, s.nowAt.Add(-time.Hour))
			s.pin(t, p, "pending_out")
			res := s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "too soon"}), TransportFacts{})
			return sealed(t, s, res, p, msgIDFor("send_message", "chain"))
		},
		"a stranger's chain-form send_message": func(t *testing.T) servedRefusal {
			s := newSealedEnv(t)
			p := newPeer(t, s.nowAt)
			return clear(t, s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "intrusion"}), TransportFacts{}))
		},
		"an envelope sealed to a key this identity no longer holds": func(t *testing.T) servedRefusal {
			s := newSealedEnv(t)
			p := newPeer(t, s.nowAt)
			s.pin(t, p, "active")
			// Sealed to today's key; the identity renews, and past the old leaf's notAfter the key
			// is gone and its kid remembered (HDTP §14.4).
			env := s.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "to the old key"})
			start := s.nowAt
			s.nowAt = start.Add(time.Hour)
			s.install(t, identity.PurposeRenew, endpointMe)
			s.nowAt = start.Add(400 * 24 * time.Hour)
			return clear(t, s.call(t, env, TransportFacts{}))
		},
		"the control: a contact's send_message": func(t *testing.T) servedRefusal {
			return contactCall(t, "send_message", nil)
		},
	}
}

// The cloud holds its hosted identity's refusals to `gateway/test/fixtures/go-refusals.json`
// (BatonDeck's test/refusal-parity.test.ts). The fixture is the node's refusals as somebody wrote
// them down, so it is checked here against what this node answers, case by case, by the whole body;
// when it differs the fixture is what moves, and the cloud's own test then says what the cloud owes.
func TestTheCloudsCopyOfTheRefusalsIsCurrent(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "batondeck", "gateway", "test", "fixtures", "go-refusals.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("SKIPPED, and so the cloud's copy is unchecked: no batondeck beside this repo (%v)", err)
	}
	var doc struct {
		Cases []refusalCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}
	drivers := servedRefusals(t)
	var named, driven []string
	for _, c := range doc.Cases {
		named = append(named, c.Name)
	}
	for n := range drivers {
		driven = append(driven, n)
	}
	sort.Strings(named)
	sort.Strings(driven)
	if strings.Join(named, "\n") != strings.Join(driven, "\n") {
		t.Fatalf("go-refusals.json and this test name different cases.\n  the fixture: %q\n  this test:   %q", named, driven)
	}
	controls := 0
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := drivers[c.Name](t)
			if got.where != c.Where {
				t.Fatalf("answered in the %s, the fixture says the %s", got.where, c.Where)
			}
			switch {
			case c.Refused != nil && !*c.Refused:
				controls++
				if got.body != nil {
					t.Fatalf("the control was refused: %v", got.body)
				}
			case c.Body != nil:
				if !reflect.DeepEqual(got.body, c.Body) {
					t.Fatalf("this node answers %v, the fixture says %v", got.body, c.Body)
				}
			case c.Shape != nil:
				if s := refusalShape(got.body); !reflect.DeepEqual(s, c.Shape) {
					t.Fatalf("this node answers %v, of shape %v; the fixture says %v", got.body, s, c.Shape)
				}
				if c.Shape["code"] == "rate_limited" && got.body["retry_after"].(float64) < 1 {
					t.Fatalf("retry_after is whole seconds, at least 1 (HDTP §12): %v", got.body)
				}
			default:
				t.Fatalf("a case with no body, shape or refused: %+v", c)
			}
		})
	}
	if controls != 1 {
		t.Fatalf("%d controls in the fixture, want one call that must be answered", controls)
	}
	if t.Failed() {
		t.Log("Change the fixture to match, and then the cloud's own test will say what the cloud owes.")
	}
}
