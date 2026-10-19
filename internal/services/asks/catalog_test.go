package asks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// surfaceOf is a surface of the given components, as an agent sends it.
func surfaceOf(components ...string) string {
	return `[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + CatalogID + `"}},` +
		`{"version":"v0.9.1","updateComponents":{"surfaceId":"s1","components":[` + strings.Join(components, ",") + `]}}]`
}

const (
	tldr     = `{"id":"tldr","component":"Text","text":"Bob proposes Wed 15:00 for 30 min."}`
	terms    = `{"id":"terms","component":"KeyValue","rows":[{"label":"When","value":"Wed 15:00"},{"label":"Length","value":"30 min"}]}`
	choice   = `{"id":"pick","component":"Choice","options":[{"label":"Confirm Wed 15:00"},{"label":"Ask for Thu instead"}]}`
	own      = `{"id":"own","component":"TextField","label":"Write my own"}`
	dateTime = `{"id":"when","component":"DateTimeInput","label":"Another time","enableDate":true,"enableTime":true,"min":"2026-10-20T09:00:00Z"}`
	okLabel  = `{"id":"ok-label","component":"Text","text":"Approve"}`
	button   = `{"id":"ok","component":"Button","child":"ok-label","variant":"primary","action":{"event":{"name":"approve","context":{"slot":"wed-15","n":1,"firm":true}}}}`
)

func root(children ...string) string {
	return `{"id":"root","component":"Column","children":["` + strings.Join(children, `","`) + `"]}`
}

// The valid corpus: each is a surface Parse accepts.
var validAsks = map[string]string{
	"the story's ask":      surfaceOf(root("tldr", "terms", "pick", "own"), tldr, terms, choice, own),
	"root anywhere":        surfaceOf(tldr, choice, root("tldr", "pick")),
	"a date and a button":  surfaceOf(root("tldr", "when", "ok"), tldr, dateTime, okLabel, button),
	"a TextField alone":    surfaceOf(root("tldr", "own"), tldr, own),
	"a date only":          surfaceOf(root("tldr", "d"), tldr, `{"id":"d","component":"DateTimeInput","enableDate":true,"max":"2026-12-31"}`),
	"multibyte, in bounds": surfaceOf(root("t", "pick"), `{"id":"t","component":"Text","text":"`+strings.Repeat("é", 140)+`"}`, choice),
	"three ready replies":  surfaceOf(root("tldr", "c"), tldr, `{"id":"c","component":"Choice","options":[{"label":"a"},{"label":"b"},{"label":"c"}]}`),
	"a heading TLDR":       surfaceOf(root("t", "pick"), `{"id":"t","component":"Text","text":"Rent: £1,450","variant":"h3"}`, choice),
}

var validNotices = map[string]string{
	"done for you": surfaceOf(root("tldr", "terms"), tldr, terms),
	"a line":       surfaceOf(root("tldr"), tldr),
}

// invalid is a surface Parse refuses, and whether the schema refuses it too: false only for the
// rules codeOnlyRules names.
type invalidCase struct {
	surface  string
	kind     string
	schema   bool // the schema refuses it as well
	tooLarge bool
}

var invalidSurfaces = map[string]invalidCase{
	"an unknown component":          {surfaceOf(root("tldr", "x"), tldr, `{"id":"x","component":"Image","url":"https://x.example/a.png"}`), KindAsk, true, false},
	"too many ready replies":        {surfaceOf(root("tldr", "c"), tldr, `{"id":"c","component":"Choice","options":[{"label":"a"},{"label":"b"},{"label":"c"},{"label":"d"}]}`), KindAsk, true, false},
	"no ready reply":                {surfaceOf(root("tldr", "c"), tldr, `{"id":"c","component":"Choice","options":[]}`), KindAsk, true, false},
	"an option with a value":        {surfaceOf(root("tldr", "c"), tldr, `{"id":"c","component":"Choice","options":[{"label":"a","value":"x"}]}`), KindAsk, true, false},
	"an unknown prop":               {surfaceOf(root("tldr", "pick"), `{"id":"tldr","component":"Text","text":"x","color":"red"}`, choice), KindAsk, true, false},
	"a wrong version":               {strings.Replace(surfaceOf(root("tldr", "pick"), tldr, choice), `"v0.9.1"`, `"v0.8"`, 1), KindAsk, true, false},
	"another catalog":               {strings.Replace(surfaceOf(root("tldr", "pick"), tldr, choice), CatalogID, "https://a2ui.org/specification/v0_9/basic_catalog.json", 1), KindAsk, true, false},
	"one message":                   {`[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + CatalogID + `"}}]`, KindAsk, true, false},
	"a data-model path":             {surfaceOf(root("tldr", "ok"), tldr, okLabel, `{"id":"ok","component":"Button","child":"ok-label","action":{"event":{"name":"go","context":{"slot":{"path":"/slot"}}}}}`), KindAsk, true, false},
	"too many rows":                 {surfaceOf(root("tldr", "kv", "pick"), tldr, `{"id":"kv","component":"KeyValue","rows":[`+strings.TrimSuffix(strings.Repeat(`{"label":"k","value":"v"},`, MaxRows+1), ",")+`]}`, choice), KindAsk, true, false},
	"a Choice in a notice":          {surfaceOf(root("tldr", "pick"), tldr, choice), KindNotice, true, false},
	"a Button in a notice":          {surfaceOf(root("tldr", "ok"), tldr, okLabel, button), KindNotice, true, false},
	"an oversize payload":           {surfaceOf(root("tldr", "pick"), tldr, choice, `{"id":"pad","component":"Text","text":"`+strings.Repeat("x", MaxSurfaceBytes)+`"}`), KindAsk, true, true},
	"a missing TLDR":                {surfaceOf(root("pick", "tldr"), tldr, choice), KindAsk, false, false},
	"a TLDR over its bound":         {surfaceOf(root("t", "pick"), `{"id":"t","component":"Text","text":"`+strings.Repeat("a", MaxTLDRBytes+1)+`"}`, choice), KindAsk, false, false},
	"a TLDR over it in bytes":       {surfaceOf(root("t", "pick"), `{"id":"t","component":"Text","text":"`+strings.Repeat("é", MaxTLDRBytes/2+1)+`"}`, choice), KindAsk, false, false},
	"no root":                       {surfaceOf(tldr, choice), KindAsk, false, false},
	"a Column not root":             {surfaceOf(root("tldr", "col"), tldr, `{"id":"col","component":"Column","children":["pick"]}`, choice), KindAsk, false, false},
	"a TextField not last":          {surfaceOf(root("tldr", "own", "pick"), tldr, own, choice), KindAsk, false, false},
	"two Choices":                   {surfaceOf(root("tldr", "pick", "c2"), tldr, choice, `{"id":"c2","component":"Choice","options":[{"label":"x"}]}`), KindAsk, false, false},
	"an ask nothing answers":        {surfaceOf(root("tldr", "terms"), tldr, terms), KindAsk, false, false},
	"a component placed twice":      {surfaceOf(root("tldr", "pick", "pick"), tldr, choice), KindAsk, true, false},
	"a component placed nowhere":    {surfaceOf(root("tldr", "pick"), tldr, choice, terms), KindAsk, false, false},
	"a child that is not there":     {surfaceOf(root("tldr", "nope", "pick"), tldr, choice), KindAsk, false, false},
	"a Button labelled by a Choice": {surfaceOf(root("tldr", "ok"), tldr, `{"id":"ok","component":"Button","child":"pick","action":{"event":{"name":"go"}}}`, choice), KindAsk, false, false},
	"two surfaceIds":                {strings.Replace(surfaceOf(root("tldr", "pick"), tldr, choice), `"surfaceId":"s1","components"`, `"surfaceId":"s2","components"`, 1), KindAsk, false, false},
	"a duplicate id":                {surfaceOf(root("tldr", "pick"), tldr, choice, `{"id":"pick","component":"Text","text":"x"}`), KindAsk, false, false},
	"a date nothing enabled":        {surfaceOf(root("tldr", "d"), tldr, `{"id":"d","component":"DateTimeInput","label":"x"}`), KindAsk, false, false},
	"a bound not ISO":               {surfaceOf(root("tldr", "d"), tldr, `{"id":"d","component":"DateTimeInput","enableDate":true,"min":"next week"}`), KindAsk, false, false},
}

func resolved(t *testing.T, kind string) *jsonschema.Resolved {
	t.Helper()
	r, err := Schema(kind).Resolve(nil)
	if err != nil {
		t.Fatalf("the %s schema does not resolve: %v", kind, err)
	}
	return r
}

func instance(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("the corpus holds a surface that is not JSON: %v", err)
	}
	return v
}

// Everything Parse accepts, the schema an agent is handed accepts too: the schema is never stricter
// than the node, so a model that follows it is never refused for it.
func TestTheSchemaAcceptsEverySurfaceTheNodeAccepts(t *testing.T) {
	for kind, corpus := range map[string]map[string]string{KindAsk: validAsks, KindNotice: validNotices} {
		r := resolved(t, kind)
		for name, s := range corpus {
			if _, err := Parse([]byte(s), kind); err != nil {
				t.Errorf("%s %q: Parse refused it: %v", kind, name, err)
			}
			if err := r.Validate(instance(t, s)); err != nil {
				t.Errorf("%s %q: the schema refused it: %v", kind, name, err)
			}
		}
	}
}

// What the catalog refuses, Parse refuses, with a path into the surface; the schema refuses it too
// unless the rule is one codeOnlyRules names, and then the schema lets it through, which is why that
// list exists. An oversize surface is too large, not malformed.
func TestTheNodeRefusesWhatTheCatalogDoesNotAllow(t *testing.T) {
	schemas := map[string]*jsonschema.Resolved{KindAsk: resolved(t, KindAsk), KindNotice: resolved(t, KindNotice)}
	for name, c := range invalidSurfaces {
		_, err := Parse([]byte(c.surface), c.kind)
		var inv Invalid
		if !errors.As(err, &inv) {
			t.Errorf("%q: Parse took it (%v)", name, err)
			continue
		}
		if !strings.HasPrefix(inv.Path, "/surface") {
			t.Errorf("%q: the refusal names no place in the surface: %v", name, inv)
		}
		if inv.TooLarge != c.tooLarge {
			t.Errorf("%q: too large %v, want %v (%v)", name, inv.TooLarge, c.tooLarge, inv)
		}
		schemaErr := schemas[c.kind].Validate(instance(t, c.surface))
		if c.schema && schemaErr == nil {
			t.Errorf("%q: the schema accepts what the node refuses (%v): it is a rule the schema should hold, or one to name in codeOnlyRules", name, inv)
		}
		if !c.schema && schemaErr != nil {
			t.Errorf("%q: the schema refuses it (%v); the case says only the node does", name, schemaErr)
		}
	}
}

// A notice's schema offers only what tells; an ask's offers every component.
func TestANoticeSchemaOffersNothingThatAnswers(t *testing.T) {
	offered := func(kind string) []string {
		b, err := json.Marshal(Schema(kind))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range catalog {
			if strings.Contains(string(b), `"const":"`+c.name+`"`) {
				out = append(out, c.name)
			}
		}
		return out
	}
	if got := strings.Join(offered(KindAsk), ","); got != "Column,Text,KeyValue,Choice,TextField,DateTimeInput,Button" {
		t.Fatalf("the ask schema offers %s", got)
	}
	if got := strings.Join(offered(KindNotice), ","); got != "Column,Text,KeyValue" {
		t.Fatalf("the notice schema offers %s", got)
	}
}

// What the node keeps is what Parse read, root first; reading it again gives the same surface.
func TestAStoredSurfaceReadsBackAsParsed(t *testing.T) {
	sf, err := Parse([]byte(validAsks["root anywhere"]), KindAsk)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Components[0].ID != "root" || sf.TLDR() != "Bob proposes Wed 15:00 for 30 min." {
		t.Fatalf("parsed: %+v", sf)
	}
	b, err := json.Marshal(storedSurface(sf))
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(b, KindAsk)
	if err != nil {
		t.Fatalf("the stored surface does not parse: %v\n%s", err, b)
	}
	pick, _ := again.Find("pick")
	if len(again.Components) != len(sf.Components) || len(pick.Options) != 2 || pick.Options[1].Label != "Ask for Thu instead" {
		t.Fatalf("read back: %+v", again)
	}
}
