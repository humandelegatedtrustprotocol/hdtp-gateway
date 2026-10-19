package webhooks

// The node's webhooks held to the cloud's (BatonDeck's gateway/src/webhooks/ and what it reads),
// read from the sibling checkout as every parity guard here reads it (testid.SiblingFile): the
// names a filter takes and the data each carries, the envelope, the signature grammar, the
// constants, the refusal codes and their words, and the views. What the two hosts do differently
// is the README's list, "Divergences from the cloud"; each entry there is a check here
// (divergences, below), and a list that names an entry this file does not check, or the reverse,
// fails. A value the cloud changes turns this red, and the node follows it or names a divergence.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// cloud is the text of one file of the batondeck checkout, by its path there.
func cloud(t *testing.T, rel string) string {
	t.Helper()
	return string(testid.SiblingFile(t, "batondeck", rel, "the webhooks' names, data, envelope, signature, constants, refusals and divergences are not compared with the cloud's"))
}

// The cloud's files this test reads.
const (
	cloudRegistry  = "gateway/src/events/registry.ts"
	cloudSign      = "gateway/src/webhooks/sign.ts"
	cloudEndpoints = "gateway/src/webhooks/endpoints.ts"
	cloudDeliver   = "gateway/src/webhooks/deliver.ts"
	cloudEnqueue   = "gateway/src/webhooks/enqueue.ts"
	cloudOutbound  = "gateway/src/net/outbound.ts"
	cloudWords     = "gateway/src/api/v1/routes/shared.ts"
	cloudRoutes    = "gateway/src/api/v1/routes/webhooks.ts"
	cloudActions   = "gateway/src/mcp/owner/actions.ts"
	cloudIdentity  = "gateway/src/identity/identity.ts"
)

// cloudEvent is one entry of the cloud's EVENT_DEFS.
type cloudEvent struct {
	name    string
	data    []string
	emitted bool
}

var eventDef = regexp.MustCompile(`\{ name: '([a-z_.]+)', summary: '(?:[^'\\]|\\.)*', data: \[([^\]]*)\], emitted: (true|false) \}`)

// cloudEvents is EVENT_DEFS in its order. SUBSCRIBABLE_EVENTS is its emitted names, as
// registry.ts derives it; the derivation is checked too, so a list written out by hand there
// turns this red rather than being read past.
func cloudEvents(t *testing.T) []cloudEvent {
	t.Helper()
	src := cloud(t, cloudRegistry)
	if !strings.Contains(src, "export const SUBSCRIBABLE_EVENTS: readonly string[] = EVENT_DEFS.filter((e) => e.emitted).map((e) => e.name)") {
		t.Fatalf("%s no longer derives SUBSCRIBABLE_EVENTS from EVENT_DEFS' emitted names: read it again", cloudRegistry)
	}
	var out []cloudEvent
	for _, m := range eventDef.FindAllStringSubmatch(src, -1) {
		out = append(out, cloudEvent{name: m[1], data: quoted(m[2]), emitted: m[3] == "true"})
	}
	// The reader's floor: the registry held 25 names when this was written. Fewer than 20 read is a
	// reader the file's layout has broken, not a cloud that dropped names.
	if len(out) < 20 {
		t.Fatalf("read %d events from %s: the reader is broken", len(out), cloudRegistry)
	}
	return out
}

var singleQuoted = regexp.MustCompile(`'([^']*)'`)

func quoted(list string) []string {
	out := []string{}
	for _, m := range singleQuoted.FindAllStringSubmatch(list, -1) {
		out = append(out, m[1])
	}
	return out
}

// cloudSubscribable is SUBSCRIBABLE_EVENTS, in the cloud's order, with each name's data keys.
func cloudSubscribable(t *testing.T) ([]string, map[string][]string) {
	t.Helper()
	var names []string
	data := map[string][]string{}
	for _, e := range cloudEvents(t) {
		if e.emitted {
			names = append(names, e.name)
			data[e.name] = e.data
		}
	}
	return names, data
}

// cloudOnly is every name the cloud sends and the node does not (README, Divergences, **Events**):
// the change row does not say which of them happened, or the node has no such fact. nodeOnly is
// every name the node sends and the cloud does not: none.
var (
	cloudOnly = []string{
		"contact.requested", "contact.accepted", "contact.rejected", "contact.removed", "contact.limit_reached",
		"booking.created", "booking.cancelled",
		"integration.attention",
		"identity.certified", "identity.renewed", "identity.imported", "identity.expiring",
		"contact.new_address", "contact.address_pending", "contact.renewed",
	}
	nodeOnly = []string{}
)

// dataSubset is every name whose data is a strict subset of the cloud's, and the keys left out
// (README, **Events**): the change row holds the request id and the caller, not the capability,
// trust flag or expiry, and a call's tool, not an integration, a mode or an outcome.
var dataSubset = map[string][]string{
	"request.pending":  {"capability", "trust_flag", "expires_at"},
	"request.answered": {"capability", "fingerprint", "relayed"},
	"call.made":        {"integration", "mode", "outcome"},
}

// sampleEvents is, for each name the node emits, an event of that name as the bus carries it, so
// the data keys compared below are the ones the node's table produces, not a copy of them.
var sampleEvents = map[string]messaging.Event{
	"message.received":  {Kind: messaging.EventMessage, Direction: messaging.DirIn, MsgID: "m1", MsgKind: "text", ThreadID: "th1", ContactFpr: "sha256:a"},
	"message.delivered": {Kind: messaging.EventDelivery, Status: messaging.StatusDelivered, MsgID: "m1", ThreadID: "th1"},
	"message.failed":    {Kind: messaging.EventDelivery, Status: messaging.StatusFailed, MsgID: "m1", ThreadID: "th1"},
	"media.received":    {Kind: messaging.EventMessage, Direction: messaging.DirIn, MsgID: "m1", MsgKind: "media", ThreadID: "th1", ContactFpr: "sha256:a"},
	"request.pending":   {Kind: messaging.EventPending, Ref: "pr-1", ContactFpr: "sha256:a"},
	"request.answered":  {Kind: messaging.EventAnswered, Ref: "pr-1"},
	"call.made":         {Kind: messaging.EventCall, Ref: core.ToolBookSlot, ContactFpr: "sha256:a"},
}

// The names a filter takes are the cloud's, in the cloud's order, less the cloud-only list; every
// name either host emits is in exactly one of: both, cloudOnly, nodeOnly.
func TestTheSubscribableNamesAreTheCloudsLessANamedList(t *testing.T) {
	theirs, _ := cloudSubscribable(t)
	ours := Subscribable()
	var both []string
	for _, n := range theirs {
		if !slices.Contains(cloudOnly, n) {
			both = append(both, n)
		}
	}
	if !slices.Equal(ours, both) {
		t.Errorf("the node offers %v; the cloud's names less cloudOnly are %v", ours, both)
	}
	for _, n := range cloudOnly {
		if !slices.Contains(theirs, n) {
			t.Errorf("cloudOnly names %s, which the cloud does not emit: take it out", n)
		}
		if slices.Contains(ours, n) {
			t.Errorf("cloudOnly names %s, which the node emits: take it out", n)
		}
	}
	for _, n := range ours {
		if !slices.Contains(theirs, n) && !slices.Contains(nodeOnly, n) {
			t.Errorf("the node emits %s, which the cloud does not, and nodeOnly does not name it", n)
		}
	}
	for _, n := range nodeOnly {
		if slices.Contains(theirs, n) || !slices.Contains(ours, n) {
			t.Errorf("nodeOnly names %s, which is not a name only the node emits", n)
		}
	}
}

// Each name carries the cloud's data keys, or a subset of them the dataSubset list names; never a
// key the cloud does not declare.
func TestEachNamesDataIsTheCloudsOrANamedSubset(t *testing.T) {
	_, theirs := cloudSubscribable(t)
	for _, m := range emitted {
		e, ok := sampleEvents[m.name]
		if !ok {
			t.Errorf("%s has no sample event here, so its data is not compared", m.name)
			continue
		}
		data, ok := m.data(e)
		if !ok {
			t.Errorf("the sample event for %s is not one the table sends as it", m.name)
			continue
		}
		var keys []string
		for k := range data {
			keys = append(keys, k)
		}
		var want []string
		for _, k := range theirs[m.name] {
			if !slices.Contains(dataSubset[m.name], k) {
				want = append(want, k)
			}
		}
		sort.Strings(keys)
		sort.Strings(want)
		if !slices.Equal(keys, want) {
			t.Errorf("%s carries %v; the cloud's %v less dataSubset's %v is %v", m.name, keys, theirs[m.name], dataSubset[m.name], want)
		}
		for _, k := range dataSubset[m.name] {
			if !slices.Contains(theirs[m.name], k) {
				t.Errorf("dataSubset leaves %s out of %s, and the cloud's %s does not carry it", k, m.name, m.name)
			}
		}
	}
	for n := range dataSubset {
		if !slices.Contains(Subscribable(), n) {
			t.Errorf("dataSubset names %s, which the node does not emit", n)
		}
	}
}

// block is the text of src from the line that starts with head to the first line after it that is
// a lone "}": one top-level function, interface or object literal of a TypeScript file.
func block(t *testing.T, src, head, file string) string {
	t.Helper()
	i := strings.Index(src, head)
	if i < 0 {
		t.Fatalf("%s has no %q: read it again", file, head)
	}
	j := strings.Index(src[i:], "\n}\n")
	if j < 0 {
		t.Fatalf("%s: %q has no end", file, head)
	}
	return src[i : i+j+2]
}

// constant is the value of `const name = <expr>` in src, where expr is a product of integers
// (`24 * 60 * 60 * 1000`, `10_000`).
func constant(t *testing.T, src, name, file string) int64 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^(?:export )?const ` + name + ` = ([0-9_ *]+)$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s has no `const %s = <number>`: read it again", file, name)
	}
	v := int64(1)
	for _, f := range strings.Split(m[1], "*") {
		n, err := strconv.ParseInt(strings.ReplaceAll(strings.TrimSpace(f), "_", ""), 10, 64)
		if err != nil {
			t.Fatalf("%s: %s = %s: %v", file, name, m[1], err)
		}
		v *= n
	}
	return v
}

// The numbers a receiver and an endpoint's owner see are the cloud's: the tolerance a verifier is
// told, the failures that pause, how long a replaced secret is accepted, how long an attempt has,
// and how much of an answer is kept.
func TestTheConstantsAreTheClouds(t *testing.T) {
	sign, endpoints, deliver := cloud(t, cloudSign), cloud(t, cloudEndpoints), cloud(t, cloudDeliver)
	for _, c := range []struct {
		name       string
		src, file  string
		cloudConst string
		node       int64
	}{
		{"ToleranceSeconds", sign, cloudSign, "TOLERANCE_SECONDS", ToleranceSeconds},
		{"FailureLimit", endpoints, cloudEndpoints, "FAILURE_LIMIT", FailureLimit},
		{"RotationWindow (ms)", endpoints, cloudEndpoints, "ROTATION_WINDOW_MS", RotationWindow.Milliseconds()},
		{"Timeout (ms)", deliver, cloudDeliver, "TIMEOUT_MS", Timeout.Milliseconds()},
		{"ExcerptBytes", deliver, cloudDeliver, "EXCERPT_BYTES", ExcerptBytes},
	} {
		if theirs := constant(t, c.src, c.cloudConst, c.file); theirs != c.node {
			t.Errorf("%s is %d; the cloud's %s is %d", c.name, c.node, c.cloudConst, theirs)
		}
	}
}

// The body is the cloud's object in the cloud's key order, identity present only when there is
// one; the ids are the cloud's prefixes.
func TestTheEnvelopeIsTheClouds(t *testing.T) {
	src := cloud(t, cloudDeliver)
	fn := block(t, src, "export function envelopeBody(", cloudDeliver)
	var theirs []string
	for _, m := range regexp.MustCompile(`(\w+): event\.(\w+)`).FindAllStringSubmatch(fn, -1) {
		if m[1] != m[2] {
			t.Fatalf("%s: envelopeBody writes %s from event.%s: read it again", cloudDeliver, m[1], m[2])
		}
		theirs = append(theirs, m[1])
	}
	if !strings.Contains(fn, "...(event.identity ? { identity: event.identity } : {})") {
		t.Fatalf("%s: envelopeBody no longer leaves identity out when there is none: read it again", cloudDeliver)
	}
	full, err := EnvelopeBody(EventEnvelope{ID: "evt_1", Type: "message.received", CreatedAt: 1, Identity: "acct", Data: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := topKeys(t, full); !slices.Equal(got, theirs) {
		t.Errorf("the node's body has keys %v; the cloud's envelopeBody writes %v", got, theirs)
	}
	bare, err := EnvelopeBody(EventEnvelope{ID: "evt_1", Type: "message.received", CreatedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := topKeys(t, bare), slices.DeleteFunc(slices.Clone(theirs), func(k string) bool { return k == "identity" }); !slices.Equal(got, want) {
		t.Errorf("with no identity the node's body has keys %v, want %v", got, want)
	}
	// The ids' prefixes: an event is evt_, an endpoint whe_ and a delivery whd_ on both hosts.
	env, ok := EnvelopeOf(store.Change{ID: 7, Kind: string(messaging.EventMessage), MsgID: "m1", Direction: string(messaging.DirIn), MsgKind: "text"}, "acct")
	if !ok {
		t.Fatal("a received message's row is not delivered")
	}
	for _, c := range []struct{ src, file, cloudID, prefix, node string }{
		{cloud(t, cloudIdentity), cloudIdentity, "id: `evt_${crypto.randomUUID()}`", "evt_", env.ID},
		{cloud(t, cloudEndpoints), cloudEndpoints, "const id = `whe_${crypto.randomUUID()}`", "whe_", newID("whe_")},
		{src, cloudDeliver, "return `whd_${crypto.randomUUID()}`", "whd_", NewDeliveryID()},
	} {
		if !strings.Contains(c.src, c.cloudID) {
			t.Errorf("%s has no %s: read it again", c.file, c.cloudID)
		}
		if !strings.HasPrefix(c.node, c.prefix) {
			t.Errorf("the node's id %q does not start with the cloud's %s", c.node, c.prefix)
		}
	}
}

// topKeys is the keys of the JSON object body, in the order they are written.
func topKeys(t *testing.T, body string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("%s is not an object", body)
	}
	var out []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, k.(string))
	}
	return out
}

// The signature is the cloud's grammar, over the cloud's signed string, under the cloud's kind of
// secret, and a receiver's verifier passes over a `v1` the cloud's would.
func TestTheSignatureIsTheClouds(t *testing.T) {
	src := cloud(t, cloudSign)
	if !strings.Contains(src, "return `${String(timestampSeconds)}.${body}`") {
		t.Fatalf("%s: signedPayload is no longer `<t>.<body>`: read it again", cloudSign)
	}
	if got := SignedPayload(1757462400, "{}"); got != "1757462400.{}" {
		t.Errorf("SignedPayload = %q, the cloud's is 1757462400.{}", got)
	}
	if !strings.Contains(src, "return `t=${String(timestampSeconds)},${parts.map((p) => `v1=${p}`).join(',')}`") {
		t.Fatalf("%s: the header is no longer t=<t>,v1=<hmac>[,v1=<hmac>]: read it again", cloudSign)
	}
	if !strings.Contains(src, "hmacSha256Hex(s, payload)") {
		t.Fatalf("%s: a v1 is no longer the hex HMAC-SHA256 of the payload under the secret: read it again", cloudSign)
	}
	h, err := Signature([]string{"whsec_new", "whsec_old"}, "{}", 1757462400)
	if err != nil {
		t.Fatal(err)
	}
	if want := "t=1757462400,v1=" + hmacHex("whsec_new", "1757462400.{}") + ",v1=" + hmacHex("whsec_old", "1757462400.{}"); h != want {
		t.Errorf("Signature = %q, want %q", h, want)
	}
	// The receiver's rule for a v1, and the secret's shape.
	if !strings.Contains(src, "key === 'v1' && /^"+strings.TrimSuffix(strings.TrimPrefix(v1Value.String(), "^"), "$")+"$/.test(value)") {
		t.Errorf("%s's verifier takes a v1 by another pattern than the node's %s", cloudSign, v1Value)
	}
	if !strings.Contains(src, "crypto.getRandomValues(new Uint8Array(32))") || !strings.Contains(src, "return `whsec_${btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '')}`") {
		t.Fatalf("%s: a secret is no longer whsec_ and 32 random bytes in unpadded base64url: read it again", cloudSign)
	}
	s, err := NewSigningSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
	if !strings.HasPrefix(s, "whsec_") || err != nil || len(raw) != 32 {
		t.Errorf("NewSigningSecret = %q: want whsec_ and 32 bytes of unpadded base64url", s)
	}
}

var (
	refusalWord = regexp.MustCompile(`(?m)^\s+(\w+): \(\) => '((?:[^'\\]|\\.)*)',$`)
	unknownWord = regexp.MustCompile("(?m)^\\s+unknown_event: \\(detail\\) => `\\$\\{detail \\?\\? 'That'\\}([^`]*)`,$")
	urlRefusal  = regexp.MustCompile(`(?s)export type UrlRefusal =((?:\s*\|\s*'[a-z_]+')+)`)
)

// cloudURLRefusals is the cloud's UrlRefusal codes.
func cloudURLRefusals(t *testing.T) []string {
	t.Helper()
	m := urlRefusal.FindStringSubmatch(cloud(t, cloudEndpoints))
	if m == nil {
		t.Fatalf("%s has no UrlRefusal union: read it again", cloudEndpoints)
	}
	return quoted(m[1])
}

// The codes the node shares with the cloud say what the cloud's say, word for word
// (WEBHOOK_REFUSALS); the ones only the cloud has are ruling A's, and the one only the node has is
// the bound on a URL's length (both in divergences).
func TestTheRefusalsTheNodeSharesAreInTheCloudsWords(t *testing.T) {
	src := cloud(t, cloudWords)
	table := block(t, src, "export const WEBHOOK_REFUSALS", cloudWords)
	theirs := map[string]string{}
	for _, m := range refusalWord.FindAllStringSubmatch(table, -1) {
		theirs[m[1]] = strings.ReplaceAll(m[2], `\'`, `'`)
	}
	u := unknownWord.FindStringSubmatch(table)
	if u == nil || len(theirs) < 2 {
		t.Fatalf("read %d plain refusals and unknown_event %v from %s: the reader is broken", len(theirs), u != nil, cloudWords)
	}
	theirs[UnknownEvent] = u[1]
	shared := []string{NotAURL, HasCredentials, UnknownEvent}
	for _, code := range shared {
		if refusalWords[code] != theirs[code] {
			t.Errorf("%s says %q; the cloud's says %q", code, refusalWords[code], theirs[code])
		}
	}
	codes := append(cloudURLRefusals(t), UnknownEvent)
	for code := range refusalWords {
		if !slices.Contains(codes, code) && code != URLTooLong {
			t.Errorf("the node refuses with %s, which the cloud does not, and no divergence names it", code)
		}
	}
	for _, code := range codes {
		if _, ok := refusalWords[code]; !ok && !slices.Contains(rulingA, code) {
			t.Errorf("the cloud refuses with %s, which the node does not, and ruling A does not name it", code)
		}
	}
}

// rulingA is the cloud's URL refusals the node does not make: only the node's owner names an
// endpoint, so http, IP literals and inward names are taken.
var rulingA = []string{"not_https", "literal_address", "private_name"}

// The views a door shows are the cloud's, field for field and in order, but for the named columns.
func TestTheViewsAreTheClouds(t *testing.T) {
	jsonKeys := func(v any) []string {
		var out []string
		ty := reflect.TypeOf(v)
		for i := range ty.NumField() {
			out = append(out, strings.Split(ty.Field(i).Tag.Get("json"), ",")[0])
		}
		return out
	}
	field := regexp.MustCompile(`(?m)^  (\w+)\??: `)
	var theirs []string
	for _, m := range field.FindAllStringSubmatch(block(t, cloud(t, cloudEndpoints), "export interface WebhookEndpointView {", cloudEndpoints), -1) {
		theirs = append(theirs, m[1])
	}
	if got := jsonKeys(EndpointView{}); !slices.Equal(got, theirs) {
		t.Errorf("EndpointView is %v; the cloud's WebhookEndpointView is %v", got, theirs)
	}
	got := jsonKeys(DeliveryView{})
	want := slices.DeleteFunc(cloudDeliveryView(t), func(k string) bool { return slices.Contains(deliveryColumnsDropped, k) })
	if !slices.Equal(got, want) {
		t.Errorf("DeliveryView is %v; the cloud's /v1 delivery less %v is %v", got, deliveryColumnsDropped, want)
	}
}

// deliveryColumnsDropped is what the cloud's /v1 shows of a delivery and the node does not: there
// is never a second attempt.
var deliveryColumnsDropped = []string{"attempt", "next_attempt_at"}

// cloudDeliveryView is the keys of a delivery as the cloud's /v1 answers it, in order.
func cloudDeliveryView(t *testing.T) []string {
	t.Helper()
	src := cloud(t, cloudRoutes)
	i := strings.Index(src, "deliveries: rows.map((r) => ({")
	j := strings.Index(src[max(i, 0):], "})),")
	if i < 0 || j < 0 {
		t.Fatalf("%s has no deliveries projection: read it again", cloudRoutes)
	}
	var out []string
	for _, m := range regexp.MustCompile(`(\w+): (?:String|Number|r\.)`).FindAllStringSubmatch(src[i:i+j], -1) {
		out = append(out, m[1])
	}
	if len(out) < 8 {
		t.Fatalf("read %v from %s's deliveries projection: the reader is broken", out, cloudRoutes)
	}
	return out
}

// readmeDivergences is the labels of the README's "Divergences from the cloud", each with the text
// of its bullet.
func readmeDivergences(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "\n## Divergences from the cloud\n")
	if i < 0 {
		t.Fatal(`README.md has no "## Divergences from the cloud"`)
	}
	s = s[i+1:]
	if j := strings.Index(s[3:], "\n## "); j >= 0 {
		s = s[:j+3]
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^- \*\*(.+?):\*\* (.*)$`).FindAllStringSubmatch(s, -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("README.md's divergences list no bullet: the reader is broken")
	}
	return out
}

// nodeTest says whether the Go file rel, from the repository's top level, declares func name: the
// tests of other packages that hold a divergence of this list.
func nodeTest(t *testing.T, rel, name string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "..", filepath.FromSlash(rel)), nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return true
		}
	}
	return false
}

var backticked = regexp.MustCompile("`([^`]+)`")

// divergences is each entry of the README's list, by its label, and what holds it: the cloud's
// side, read from its source, and the node's.
var divergences = map[string]func(t *testing.T, bullet string){
	"URLs (ruling A)": func(t *testing.T, bullet string) {
		theirs := cloudURLRefusals(t)
		for _, code := range rulingA {
			if !slices.Contains(theirs, code) {
				t.Errorf("ruling A names %s, which the cloud no longer refuses", code)
			}
			if !strings.Contains(bullet, "`"+code+"`") {
				t.Errorf("the README's URLs entry does not name %s", code)
			}
		}
		if !regexp.MustCompile(`protocol !== 'https:'\) return 'not_https'`).MatchString(cloud(t, cloudEndpoints)) {
			t.Errorf("%s no longer refuses a scheme other than https as not_https", cloudEndpoints)
		}
		for raw, want := range map[string]string{
			"http://127.0.0.1:8080/hook": "", "http://localhost/hook": "", "https://agent.internal/hook": "",
			"http://[::1]/hook": "", "http://agent.local/hook": "", "ftp://receiver.example/hook": NotAURL,
		} {
			if got := CheckEndpointURL(raw); got != want {
				t.Errorf("CheckEndpointURL(%s) = %q, want %q", raw, got, want)
			}
		}
	},
	"Headers": func(t *testing.T, bullet string) {
		src := cloud(t, cloudSign)
		for cloudName, node := range map[string]string{
			"SIGNATURE_HEADER": SignatureHeader, "EVENT_ID_HEADER": EventIDHeader,
			"EVENT_TYPE_HEADER": EventTypeHeader, "DELIVERY_HEADER": DeliveryHeader,
		} {
			m := regexp.MustCompile(`export const ` + cloudName + ` = 'X-BatonDeck-([A-Za-z-]+)'`).FindStringSubmatch(src)
			if m == nil {
				t.Errorf("%s has no %s = 'X-BatonDeck-…'", cloudSign, cloudName)
				continue
			}
			if node != "X-HDTP-"+m[1] {
				t.Errorf("the node's %s is %s; the cloud's is X-BatonDeck-%s", cloudName, node, m[1])
			}
		}
		if !strings.Contains(cloud(t, cloudDeliver), "'user-agent': 'BatonDeck-Webhooks/1'") {
			t.Errorf("%s no longer sends the user agent BatonDeck-Webhooks/1", cloudDeliver)
		}
		if agent := NewDispatcher(nil, nil, nil, "9.9.9", nil).agent; agent != "hdtp-gateway-webhooks/9.9.9" {
			t.Errorf("the node's user agent is %s", agent)
		}
		for _, name := range []string{"BatonDeck-Webhooks/1", "hdtp-gateway-webhooks/<version>"} {
			if !strings.Contains(bullet, "`"+name+"`") {
				t.Errorf("the README's Headers entry does not name %s", name)
			}
		}
	},
	"The envelope's `identity`": func(t *testing.T, bullet string) {
		if !regexp.MustCompile(`identity: this\.store\.account\(\)!?\.slug`).MatchString(cloud(t, cloudIdentity)) {
			t.Errorf("%s no longer sends the identity's slug as the envelope's identity", cloudIdentity)
		}
		const holder = "TestTheEnvelopesIdentityIsTheAccountIDWhereTheCloudSendsTheSlug"
		if !nodeTest(t, "internal/services/webhooks/identity_divergence_test.go", holder) || !strings.Contains(bullet, holder) {
			t.Errorf("%s does not hold the identity entry, or the README does not name it", holder)
		}
	},
	"Delivery rows": func(t *testing.T, bullet string) {
		row := block(t, cloud(t, cloudDeliver), "export interface DeliveryRow extends Row {", cloudDeliver)
		dropped := append(slices.Clone(deliveryColumnsDropped), "payload_json")
		for _, col := range dropped {
			if !strings.Contains(row, "\n  "+col+": ") {
				t.Errorf("the cloud's DeliveryRow has no %s", col)
			}
			if !strings.Contains(bullet, "`"+col+"`") && !strings.Contains(bullet, "`"+strings.TrimSuffix(col, "_at")+"`") {
				t.Errorf("the README's Delivery rows entry does not name %s", col)
			}
		}
		ty := reflect.TypeOf(store.WebhookDelivery{})
		for i := range ty.NumField() {
			if n := strings.ToLower(ty.Field(i).Name); strings.Contains(n, "attempt") || strings.Contains(n, "payload") {
				t.Errorf("the node's delivery row has %s", ty.Field(i).Name)
			}
		}
	},
	"No queue": func(t *testing.T, bullet string) {
		if !strings.Contains(cloud(t, cloudEnqueue), "export async function enqueueEvent(") {
			t.Errorf("%s no longer enqueues an event", cloudEnqueue)
		}
		if _, ok := reflect.TypeFor[store.Store]().MethodByName("ClaimWebhookCursor"); !ok {
			t.Error("the node's store has no ClaimWebhookCursor: the dispatcher reads no cursor")
		}
	},
	"Redirects": func(t *testing.T, bullet string) {
		attempt := block(t, cloud(t, cloudDeliver), "export async function attemptDelivery(", cloudDeliver)
		fetch := block(t, cloud(t, cloudOutbound), "export function networkFetch(", cloudOutbound)
		if strings.Contains(attempt, "redirect") || strings.Contains(fetch, "redirect") {
			t.Errorf("the cloud's delivery now names a redirect mode: the README's Redirects entry says it follows one")
		}
		if !strings.Contains(bullet, "where the cloud follows them") {
			t.Errorf("the README's Redirects entry does not say the cloud follows a redirect: %s", bullet)
		}
		d := NewDispatcher(nil, nil, nil, "", nil)
		if d.client.CheckRedirect == nil || d.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Error("the node's dispatcher follows a redirect")
		}
	},
	"Bounds": func(t *testing.T, bullet string) {
		list := block(t, cloud(t, cloudEndpoints), "export async function listEndpoints(", cloudEndpoints)
		if !strings.Contains(list, "limit: "+strconv.Itoa(EndpointLimit)) {
			t.Errorf("the cloud's listEndpoints no longer lists %d", EndpointLimit)
		}
		create := block(t, cloud(t, cloudEndpoints), "export async function createEndpoint(", cloudEndpoints)
		if strings.Contains(create, "count") || strings.Contains(create, "limit") {
			t.Error("the cloud's createEndpoint now counts or limits: the README's Bounds entry says it refuses no endpoint for their number")
		}
		if slices.Contains(cloudURLRefusals(t), URLTooLong) {
			t.Errorf("the cloud now refuses %s", URLTooLong)
		}
		if CheckEndpointURL("https://receiver.example/"+strings.Repeat("a", MaxURLBytes)) != URLTooLong {
			t.Error("the node takes a URL over MaxURLBytes")
		}
	},
	"Doors": func(t *testing.T, bullet string) {
		var theirs []string
		for _, m := range regexp.MustCompile(`action: '(\w*webhook\w*)'`).FindAllStringSubmatch(cloud(t, cloudActions), -1) {
			theirs = append(theirs, m[1])
		}
		var named []string
		for _, m := range backticked.FindAllStringSubmatch(bullet, -1) {
			if strings.Contains(m[1], "webhook") && !strings.Contains(m[1], "/") {
				named = append(named, m[1])
			}
		}
		if len(theirs) == 0 || !slices.Equal(named, theirs) {
			t.Errorf("the cloud's owner MCP has the webhook actions %v; the README's Doors entry names %v", theirs, named)
		}
		for rel, name := range map[string]string{
			"internal/internalui/ownermcp/webhook_divergence_test.go": "TestNoOwnerMCPToolTouchesAWebhook",
			"internal/cli/webhook_divergence_test.go":                 "TestNoCommandTouchesAWebhook",
		} {
			if !nodeTest(t, rel, name) || !strings.Contains(bullet, name) {
				t.Errorf("%s (%s) does not hold the Doors entry, or the README does not name it", name, rel)
			}
		}
	},
	"Audit names": func(t *testing.T, bullet string) {
		var theirs []string
		for _, m := range regexp.MustCompile(`orgEvent\(ctx, '(webhook\.[a-z_]+)'`).FindAllStringSubmatch(cloud(t, cloudRoutes), -1) {
			theirs = append(theirs, m[1])
		}
		if !slices.Contains(theirs, "webhook.created") {
			t.Errorf("the cloud audits %v, not webhook.created", theirs)
		}
		f := newFixture(t)
		ctx := context.Background()
		v, _ := f.create(t, "http://127.0.0.1/hook")
		_, _, _ = f.svc.Rotate(ctx, f.mine, v.ID)
		_ = f.svc.SetStatus(ctx, f.mine, v.ID, "paused")
		_ = f.svc.SetStatus(ctx, f.mine, v.ID, "active")
		_ = f.svc.Remove(ctx, f.mine, v.ID)
		lines := f.log.take()
		if len(lines) != 5 {
			t.Fatalf("five calls wrote %v", lines)
		}
		for _, l := range lines {
			action := strings.Fields(l)[0]
			if !regexp.MustCompile(`^webhook_[a-z]+$`).MatchString(action) || slices.Contains(theirs, action) {
				t.Errorf("the node audits %s, which is not the node's snake_case", action)
			}
		}
	},
	"Events": func(t *testing.T, bullet string) {
		var families []string
		for _, m := range backticked.FindAllStringSubmatch(bullet, -1) {
			families = append(families, m[1])
		}
		for _, n := range cloudOnly {
			named := false
			for _, f := range families {
				if f == n || (strings.HasSuffix(f, ".*") && strings.HasPrefix(n, strings.TrimSuffix(f, "*"))) {
					named = true
				}
			}
			if !named {
				t.Errorf("cloudOnly names %s, which the README's Events entry does not", n)
			}
		}
		for n := range dataSubset {
			if !slices.Contains(families, n) {
				t.Errorf("dataSubset names %s, which the README's Events entry does not", n)
			}
		}
	},
}

// The README's list and this file's are one list: an entry the README names that nothing here
// holds fails, and so does one held here that the README does not name. Each is then checked.
func TestEveryDivergenceTheREADMENamesIsHeldAndNoOther(t *testing.T) {
	named := readmeDivergences(t)
	for label := range named {
		if _, ok := divergences[label]; !ok {
			t.Errorf("the README names the divergence %q, and nothing here holds it", label)
		}
	}
	for label := range divergences {
		if _, ok := named[label]; !ok {
			t.Errorf("a divergence %q is held here, and the README does not name it", label)
		}
	}
	for label, check := range divergences {
		if bullet, ok := named[label]; ok {
			t.Run(label, func(t *testing.T) { check(t, bullet) })
		}
	}
}
