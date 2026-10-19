package asks

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// surfaceOf is a surface of the given components, as an agent sends it.
func surfaceOf(components ...string) string {
	return `[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + CatalogID + `"}},` +
		`{"version":"v0.9.1","updateComponents":{"surfaceId":"s1","components":[` + strings.Join(components, ",") + `]}}]`
}

// withModel is surface with an updateDataModel message after it, holding model.
func withModel(surface, model string) string {
	return strings.TrimSuffix(surface, "]") + `,{"version":"v0.9.1","updateDataModel":{"surfaceId":"s1","value":` + model + `}}]`
}

const (
	tldr     = `{"id":"tldr","component":"Text","text":"Bob proposes Wed 15:00 for 30 min."}`
	terms    = `{"id":"terms","component":"KeyValue","items":[{"label":"When","value":"Wed 15:00"},{"label":"Length","value":"30 min"}]}`
	choice   = `{"id":"pick","component":"ChoicePicker","variant":"mutuallyExclusive","options":[{"label":"Confirm Wed 15:00","value":"confirm"},{"label":"Ask for Thu instead","value":"thu"}],"value":{"path":"/reply"}}`
	own      = `{"id":"own","component":"TextField","label":"Write my own","value":{"path":"/own"}}`
	dateTime = `{"id":"when","component":"DateTimeInput","label":"Another time","enableDate":true,"enableTime":true,"min":"2026-10-20T09:00:00Z","value":{"path":"/when"}}`
	okLabel  = `{"id":"ok-label","component":"Text","text":"Approve"}`
	button   = `{"id":"ok","component":"Button","child":"ok-label","variant":"primary","action":{"event":{"name":"approve","context":{"slot":"wed-15","n":1,"firm":true}}}}`
	// send is the button that sends what the owner chose or wrote.
	sendLabel = `{"id":"send-label","component":"Text","text":"Send"}`
	send      = `{"id":"send","component":"Button","child":"send-label","variant":"primary","action":{"event":{"name":"answer","context":{"reply":{"path":"/reply"},"own":{"path":"/own"}}}}}`
	sendWhen  = `{"id":"send","component":"Button","child":"send-label","action":{"event":{"name":"answer","context":{"when":{"path":"/when"},"own":{"path":"/own"}}}}}`
	sendOwn   = `{"id":"send","component":"Button","child":"send-label","variant":"primary","action":{"event":{"name":"answer","context":{"own":{"path":"/own"}}}}}`
	// The ready replies: a Button each, its reply the literal one tap sends.
	confirmLabel = `{"id":"r1-label","component":"Text","text":"Confirm Wed 15:00"}`
	confirm      = `{"id":"r1","component":"Button","child":"r1-label","action":{"event":{"name":"reply","context":{"reply":"Confirm Wed 15:00"}}}}`
	thuLabel     = `{"id":"r2-label","component":"Text","text":"Ask for Thu instead"}`
	thu          = `{"id":"r2","component":"Button","child":"r2-label","action":{"event":{"name":"reply","context":{"reply":"Ask for Thu instead"}}}}`
)

// replyButton is a ready reply's Button and its label, id n, sending text.
func replyButton(n, text string) string {
	return `{"id":"` + n + `-label","component":"Text","text":"` + text + `"},` +
		`{"id":"` + n + `","component":"Button","child":"` + n + `-label","action":{"event":{"name":"reply","context":{"reply":"` + text + `"}}}}`
}

func root(children ...string) string {
	return `{"id":"root","component":"Column","children":["` + strings.Join(children, `","`) + `"]}`
}

// story is the use-case series' ask: the TLDR, the terms, two ready replies of one tap each, and
// write my own with its Send.
var story = surfaceOf(root("tldr", "terms", "r1", "r2", "own", "send"), tldr, terms, confirmLabel, confirm, thuLabel, thu, own, sendLabel, sendOwn)

// pickAsk is an ask whose options the owner picks one of, then sends with what they wrote.
var pickAsk = surfaceOf(root("tldr", "terms", "pick", "own", "send"), tldr, terms, choice, own, sendLabel, send)

// ending is how every ask ends, root's last two children: write my own, then the Button that sends
// it.
const ending = own + "," + sendLabel + "," + sendOwn

// askRoot is an ask's root: children, then write my own and its Send.
func askRoot(children ...string) string { return root(append(children, "own", "send")...) }

// The valid corpus: each is a surface Parse accepts.
var validAsks = map[string]string{
	"the story's ask":          story,
	"the story with its model": withModel(story, `{"own":""}`),
	"three ready replies":      surfaceOf(askRoot("tldr", "a", "b", "c"), tldr, replyButton("a", "Yes"), replyButton("b", "No"), replyButton("c", "Later"), ending),
	"a picker and its Send":    pickAsk,
	"with its data model":      withModel(pickAsk, `{"reply":["confirm"],"own":""}`),
	"a model nested in bounds": withModel(surfaceOf(root("tldr", "pick", "own", "send"), tldr, strings.Replace(choice, `"/reply"`, `"/a/b/reply"`, 1), own, sendLabel, strings.Replace(send, `"/reply"`, `"/a/b/reply"`, 1)), `{"a":{"b":{"reply":[]}}}`),
	"a date and a button":      surfaceOf(askRoot("tldr", "when", "ok"), tldr, dateTime, okLabel, button, ending),
	"a date it sends":          surfaceOf(root("tldr", "when", "own", "send"), tldr, dateTime, own, sendLabel, sendWhen),
	"a TextField alone":        surfaceOf(askRoot("tldr"), tldr, ending),
	"a date only":              surfaceOf(askRoot("tldr", "d", "ok"), tldr, `{"id":"d","component":"DateTimeInput","enableDate":true,"max":"2026-12-31","value":{"path":"/d"}}`, okLabel, button, ending),
	"multibyte, in bounds":     surfaceOf(askRoot("t", "ok"), `{"id":"t","component":"Text","text":"`+strings.Repeat("é", 140)+`"}`, okLabel, button, ending),
	"three options":            surfaceOf(root("tldr", "c", "own", "send"), tldr, `{"id":"c","component":"ChoicePicker","options":[{"label":"a","value":"a"},{"label":"b","value":"b"},{"label":"c","value":"c"}],"value":{"path":"/reply"}}`, own, sendLabel, send),
	"a heading TLDR":           surfaceOf(askRoot("t", "ok"), `{"id":"t","component":"Text","text":"Rent: £1,450","variant":"h3"}`, okLabel, button, ending),
	"a button with no context": surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, `{"id":"ok","component":"Button","child":"ok-label","action":{"event":{"name":"seen"}}}`, ending),
}

var validNotices = map[string]string{
	"done for you": surfaceOf(root("tldr", "terms"), tldr, terms),
	"a line":       surfaceOf(root("tldr"), tldr),
}

// invalid is a surface Parse refuses, and whether the schema refuses it too: false only for the
// code-only rules catalog.go names.
type invalidCase struct {
	surface  string
	kind     string
	schema   bool // the schema refuses it as well
	tooLarge bool
	rule     string // the rule that refuses it, Invalid.Rule
}

// withPicker is an ask of picker c, a ChoicePicker bound to /reply, ending with write my own and the
// Send that reads both.
func withPicker(c string) string {
	return surfaceOf(root("tldr", "c", "own", "send"), tldr, c, own, sendLabel, send)
}

var invalidSurfaces = map[string]invalidCase{
	"an unknown component":          {surfaceOf(askRoot("tldr", "x", "ok"), tldr, `{"id":"x","component":"Image","url":"https://x.example/a.png"}`, okLabel, button, ending), KindAsk, true, false, "unknown_component"},
	"too many ready replies":        {withPicker(`{"id":"c","component":"ChoicePicker","options":[{"label":"a","value":"a"},{"label":"b","value":"b"},{"label":"c","value":"c"},{"label":"d","value":"d"}],"value":{"path":"/reply"}}`), KindAsk, true, false, "prop_size"},
	"no ready reply":                {withPicker(`{"id":"c","component":"ChoicePicker","options":[],"value":{"path":"/reply"}}`), KindAsk, true, false, "prop_value"},
	"an option with no value":       {withPicker(`{"id":"c","component":"ChoicePicker","options":[{"label":"a"}],"value":{"path":"/reply"}}`), KindAsk, true, false, "prop_value"},
	"two options of one value":      {withPicker(`{"id":"c","component":"ChoicePicker","options":[{"label":"a","value":"x"},{"label":"b","value":"x"}],"value":{"path":"/reply"}}`), KindAsk, false, false, "option_values"},
	"a picker of many":              {withPicker(strings.Replace(strings.Replace(choice, "mutuallyExclusive", "multipleSelection", 1), `"id":"pick"`, `"id":"c"`, 1)), KindAsk, true, false, "prop_value"},
	"a picker bound to nothing":     {surfaceOf(askRoot("tldr", "pick", "ok"), tldr, strings.Replace(choice, `,"value":{"path":"/reply"}`, "", 1), okLabel, button, ending), KindAsk, true, false, "required_prop"},
	"a literal picker value":        {surfaceOf(askRoot("tldr", "pick", "ok"), tldr, strings.Replace(choice, `{"path":"/reply"}`, `["confirm"]`, 1), okLabel, button, ending), KindAsk, true, false, "binding"},
	"a TextField with no label":     {surfaceOf(askRoot("tldr"), tldr, `{"id":"own","component":"TextField","value":{"path":"/own"}}`, sendLabel, sendOwn), KindAsk, true, false, "required_prop"},
	"a relative path":               {surfaceOf(askRoot("tldr"), tldr, strings.Replace(own, `"/own"`, `"own"`, 1), sendLabel, sendOwn), KindAsk, true, false, "binding"},
	"a binding with a function":     {surfaceOf(askRoot("tldr"), tldr, strings.Replace(own, `{"path":"/own"}`, `{"path":"/own","call":"x"}`, 1), sendLabel, sendOwn), KindAsk, true, false, "binding"},
	"a function call action":        {surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, `{"id":"ok","component":"Button","child":"ok-label","action":{"functionCall":{"call":"openUrl","args":{"url":"https://x.example"}}}}`, ending), KindAsk, true, false, "action_function"},
	"a context of an object":        {surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, `{"id":"ok","component":"Button","child":"ok-label","action":{"event":{"name":"go","context":{"x":{"a":1}}}}}`, ending), KindAsk, true, false, "binding"},
	"a path no input binds":         {surfaceOf(root("tldr", "pick", "own", "send"), tldr, choice, own, sendLabel, strings.Replace(send, `"/reply"`, `"/elsewhere"`, 1)), KindAsk, false, false, "context_unbound"},
	"two inputs on one path":        {surfaceOf(root("tldr", "pick", "own", "send"), tldr, choice, strings.Replace(own, `"/own"`, `"/reply"`, 1), sendLabel, send), KindAsk, false, false, "binding_shared"},
	"an input inside another's":     {surfaceOf(root("tldr", "pick", "own", "send"), tldr, choice, strings.Replace(own, `"/own"`, `"/reply/own"`, 1), sendLabel, send), KindAsk, false, false, "binding_shared"},
	"an unknown prop":               {surfaceOf(askRoot("tldr", "ok"), `{"id":"tldr","component":"Text","text":"x","color":"red"}`, okLabel, button, ending), KindAsk, true, false, "unknown_prop"},
	"a check on an input":           {surfaceOf(askRoot("tldr"), tldr, strings.Replace(own, `"label"`, `"checks":[],"label"`, 1), sendLabel, sendOwn), KindAsk, true, false, "unknown_prop"},
	"a wrong version":               {strings.Replace(story, `"v0.9.1"`, `"v0.8"`, 1), KindAsk, true, false, "version"},
	"another catalog":               {strings.Replace(story, CatalogID, "https://a2ui.org/specification/v0_9/basic_catalog.json", 1), KindAsk, true, false, "catalog_id"},
	"one message":                   {`[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + CatalogID + `"}}]`, KindAsk, true, false, "messages"},
	"too many items":                {surfaceOf(askRoot("tldr", "kv", "ok"), tldr, `{"id":"kv","component":"KeyValue","items":[`+strings.TrimSuffix(strings.Repeat(`{"label":"k","value":"v"},`, MaxItems+1), ",")+`]}`, okLabel, button, ending), KindAsk, true, false, "prop_size"},
	"the old rows":                  {surfaceOf(askRoot("tldr", "kv", "ok"), tldr, `{"id":"kv","component":"KeyValue","rows":[{"label":"k","value":"v"}]}`, okLabel, button, ending), KindAsk, true, false, "unknown_prop"},
	"a ChoicePicker in a notice":    {surfaceOf(root("tldr", "pick"), tldr, choice), KindNotice, true, false, "unknown_component"},
	"a Button in a notice":          {surfaceOf(root("tldr", "ok"), tldr, okLabel, button), KindNotice, true, false, "unknown_component"},
	"a data model in a notice":      {withModel(surfaceOf(root("tldr"), tldr), `{}`), KindNotice, true, false, "messages"},
	"a data model at a path":        {strings.Replace(withModel(pickAsk, `{"reply":[]}`), `"updateDataModel":{"surfaceId":"s1"`, `"updateDataModel":{"surfaceId":"s1","path":"/reply"`, 1), KindAsk, true, false, "model_path"},
	"a data model not an object":    {withModel(pickAsk, `["confirm"]`), KindAsk, true, false, "model_shape"},
	"a data model too deep":         {withModel(pickAsk, `{"a":{"b":{"c":{"d":{"e":1}}}}}`), KindAsk, false, false, "model_depth"},
	"a choice not an option":        {withModel(pickAsk, `{"reply":["maybe"]}`), KindAsk, false, false, "model_value"},
	"two choices of one":            {withModel(pickAsk, `{"reply":["confirm","thu"]}`), KindAsk, false, false, "model_value"},
	"a text of a number":            {withModel(pickAsk, `{"own":3}`), KindAsk, false, false, "model_value"},
	"a data model of another":       {strings.Replace(withModel(pickAsk, `{}`), `"updateDataModel":{"surfaceId":"s1"`, `"updateDataModel":{"surfaceId":"s2"`, 1), KindAsk, false, false, "surface_id"},
	"an oversize payload":           {surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, button, ending, `{"id":"pad","component":"Text","text":"`+strings.Repeat("x", MaxSurfaceBytes)+`"}`), KindAsk, true, true, "surface_size"},
	"a missing TLDR":                {surfaceOf(root("pick", "tldr", "own", "send"), tldr, choice, own, sendLabel, send), KindAsk, false, false, "tldr_first_child"},
	"a TLDR over its bound":         {surfaceOf(askRoot("t", "ok"), `{"id":"t","component":"Text","text":"`+strings.Repeat("a", MaxTLDRBytes+1)+`"}`, okLabel, button, ending), KindAsk, false, false, "tldr_size"},
	"a TLDR over it in bytes":       {surfaceOf(askRoot("t", "ok"), `{"id":"t","component":"Text","text":"`+strings.Repeat("é", MaxTLDRBytes/2+1)+`"}`, okLabel, button, ending), KindAsk, false, false, "tldr_size"},
	"no root":                       {surfaceOf(tldr, okLabel, button, ending), KindAsk, true, false, "root_missing"},
	"a Column not root":             {surfaceOf(askRoot("tldr", "col", "ok"), tldr, `{"id":"col","component":"Column","children":["terms"]}`, terms, okLabel, button, ending), KindAsk, true, false, "column_not_root"},
	"root not first":                {surfaceOf(tldr, askRoot("tldr", "ok"), okLabel, button, ending), KindAsk, true, false, "root_first"},
	"root not first, a Text second": {surfaceOf(okLabel, tldr, button, askRoot("tldr", "ok"), ending), KindAsk, true, false, "root_first"},
	"something else second":         {surfaceOf(askRoot("tldr", "terms", "ok"), terms, tldr, okLabel, button, ending), KindAsk, true, false, "tldr_second"},
	"a Text second, not the TLDR":   {surfaceOf(askRoot("tldr", "ok"), okLabel, tldr, button, ending), KindAsk, false, false, "tldr_second"},
	"four ready replies":            {surfaceOf(askRoot("tldr", "a", "b", "c", "d"), tldr, replyButton("a", "1"), replyButton("b", "2"), replyButton("c", "3"), replyButton("d", "4"), ending), KindAsk, true, false, "reply_count"},
	"a reply with no text":          {surfaceOf(askRoot("tldr", "r1"), tldr, confirmLabel, strings.Replace(confirm, `"reply":"Confirm Wed 15:00"`, `"reply":" "`, 1), ending), KindAsk, false, false, "prop_value"},
	"a reply with no context":       {surfaceOf(askRoot("tldr", "r1"), tldr, confirmLabel, strings.Replace(confirm, `,"context":{"reply":"Confirm Wed 15:00"}`, "", 1), ending), KindAsk, true, false, "reply_context"},
	"a reply bound to a path":       {surfaceOf(askRoot("tldr", "r1"), tldr, confirmLabel, strings.Replace(confirm, `"Confirm Wed 15:00"}`, `{"path":"/own"}}`, 1), ending), KindAsk, true, false, "prop_value"},
	"a reply with another key":      {surfaceOf(askRoot("tldr", "r1"), tldr, confirmLabel, strings.Replace(confirm, `"reply":"Confirm Wed 15:00"`, `"reply":"Confirm Wed 15:00","n":1`, 1), ending), KindAsk, true, false, "reply_context"},
	"a reply over its bound":        {surfaceOf(askRoot("tldr", "r1"), tldr, confirmLabel, strings.Replace(confirm, `"Confirm Wed 15:00"}`, `"`+strings.Repeat("x", 281)+`"}`, 1), ending), KindAsk, true, false, "prop_size"},
	"two ChoicePickers":             {surfaceOf(root("tldr", "pick", "c2", "own", "send"), tldr, choice, `{"id":"c2","component":"ChoicePicker","options":[{"label":"x","value":"x"}],"value":{"path":"/c2"}}`, own, sendLabel, send), KindAsk, true, false, "input_count"},
	"two TextFields":                {surfaceOf(root("tldr", "o2", "own", "send"), tldr, strings.Replace(strings.Replace(own, `"own"`, `"o2"`, 1), `"/own"`, `"/o2"`, 1), own, sendLabel, sendOwn), KindAsk, true, false, "input_count"},
	"a component placed twice":      {surfaceOf(askRoot("tldr", "ok", "ok"), tldr, okLabel, button, ending), KindAsk, true, false, "placed_twice"},
	"a component placed nowhere":    {surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, button, ending, terms), KindAsk, false, false, "placed_nowhere"},
	"a child that is not there":     {surfaceOf(askRoot("tldr", "nope", "ok"), tldr, okLabel, button, ending), KindAsk, false, false, "child_missing"},
	"a Button labelled by a field":  {surfaceOf(askRoot("tldr", "ok"), tldr, terms, strings.Replace(button, `"child":"ok-label"`, `"child":"terms"`, 1), ending), KindAsk, false, false, "button_label"},
	"two surfaceIds":                {strings.Replace(story, `"surfaceId":"s1","components"`, `"surfaceId":"s2","components"`, 1), KindAsk, false, false, "surface_id"},
	"a duplicate id":                {surfaceOf(askRoot("tldr", "ok"), tldr, okLabel, button, ending, `{"id":"ok","component":"Text","text":"x"}`), KindAsk, false, false, "duplicate_id"},
	"a date nothing enabled":        {surfaceOf(askRoot("tldr", "d", "ok"), tldr, `{"id":"d","component":"DateTimeInput","label":"x","value":{"path":"/d"}}`, okLabel, button, ending), KindAsk, false, false, "date_enables"},
	"a bound not ISO":               {surfaceOf(askRoot("tldr", "d", "ok"), tldr, `{"id":"d","component":"DateTimeInput","enableDate":true,"min":"next week","value":{"path":"/d"}}`, okLabel, button, ending), KindAsk, false, false, "prop_value"},
	// The owner's own message ends every ask: write my own, then the Button that sends it.
	"no write my own":               {surfaceOf(root("tldr", "r1", "ok"), tldr, confirmLabel, confirm, okLabel, button), KindAsk, true, false, "own_message"},
	"an ask nothing answers":        {surfaceOf(root("tldr", "terms", "own"), tldr, terms, own), KindAsk, true, false, "own_message"},
	"ready replies and no Send":     {surfaceOf(root("tldr", "own", "r1"), tldr, own, confirmLabel, confirm), KindAsk, true, false, "own_message"},
	"write my own not next-to-last": {surfaceOf(root("tldr", "own", "r1", "send"), tldr, own, confirmLabel, confirm, sendLabel, sendOwn), KindAsk, false, false, "own_message"},
	"a TextField not last":          {surfaceOf(root("tldr", "own", "pick", "send"), tldr, own, choice, sendLabel, send), KindAsk, false, false, "own_message"},
	"a ready reply after Send":      {surfaceOf(root("tldr", "own", "send", "r1"), tldr, own, sendLabel, sendOwn, confirmLabel, confirm), KindAsk, false, false, "own_message"},
	"a last Button that drops it":   {surfaceOf(root("tldr", "own", "ok"), tldr, own, okLabel, button), KindAsk, false, false, "own_message"},
	"only a TLDR":                   {surfaceOf(root("tldr"), tldr), KindAsk, true, false, "own_message"},
	"a Text after write my own":     {surfaceOf(root("tldr", "own", "terms"), tldr, own, terms), KindAsk, true, false, "own_message"},
	"only a TLDR and write my own":  {surfaceOf(root("tldr", "own"), tldr, own), KindAsk, true, false, "own_message"},
}

// schemaOf is the document an agent is handed for a surface of kind: SurfaceSchema with Defs at its
// root, as PutSchema carries them.
func schemaOf(kind string) *jsonschema.Schema {
	s := SurfaceSchema(kind)
	s.Defs = Defs(kind)
	return s
}

func resolved(t *testing.T, kind string) *jsonschema.Resolved {
	t.Helper()
	r, err := schemaOf(kind).Resolve(nil)
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
// unless the rule is one of the code-only rules catalog.go names, and then the schema lets it through, which is why that
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
		if inv.Rule != c.rule || inv.Reason() != "invalid_surface:"+c.rule {
			t.Errorf("%q: refused by rule %q (reason %q), want %q", name, inv.Rule, inv.Reason(), c.rule)
		}
		if inv.TooLarge != c.tooLarge {
			t.Errorf("%q: too large %v, want %v (%v)", name, inv.TooLarge, c.tooLarge, inv)
		}
		schemaErr := schemas[c.kind].Validate(instance(t, c.surface))
		if c.schema && schemaErr == nil {
			t.Errorf("%q: the schema accepts what the node refuses (%v): it is a rule the schema should hold, or one to name among catalog.go's code-only rules", name, inv)
		}
		if !c.schema && schemaErr != nil {
			t.Errorf("%q: the schema refuses it (%v); the case says only the node does", name, schemaErr)
		}
	}
}

// A notice's schema offers only what tells; an ask's offers every component.
func TestANoticeSchemaOffersNothingThatAnswers(t *testing.T) {
	offered := func(kind string) []string {
		b, err := json.Marshal(schemaOf(kind))
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
	if got := strings.Join(offered(KindAsk), ","); got != "Column,Text,KeyValue,ChoicePicker,TextField,DateTimeInput,Button" {
		t.Fatalf("the ask schema offers %s", got)
	}
	if got := strings.Join(offered(KindNotice), ","); got != "Column,Text,KeyValue" {
		t.Fatalf("the notice schema offers %s", got)
	}
}

// What the node keeps is what Parse read, root first, its data model with it; reading it again gives
// the same surface.
func TestAStoredSurfaceReadsBackAsParsed(t *testing.T) {
	sf, err := Parse([]byte(withModel(validAsks["a picker and its Send"], `{"reply":["thu"],"own":""}`)), KindAsk)
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
	if len(again.Components) != len(sf.Components) || len(pick.Options) != 2 || pick.Options[1] != (Item{Label: "Ask for Thu instead", Value: "thu"}) ||
		pick.Value == nil || pick.Value.Path != "/reply" {
		t.Fatalf("read back: %+v", again)
	}
	if v, ok := lookup(again.Model, "/reply"); !ok || len(v.([]any)) != 1 || v.([]any)[0] != "thu" {
		t.Fatalf("the data model read back: %v", again.Model)
	}
	// With no data model, none is kept.
	sf, _ = Parse([]byte(story), KindAsk)
	if b, _ := json.Marshal(storedSurface(sf)); strings.Contains(string(b), "updateDataModel") {
		t.Fatalf("a data model was made up: %s", b)
	}
}

// The catalog is the node's own, as A2UI provides for: it names A2UI's basic components with their
// properties' shapes, and KeyValue, the node's own. Every prop the catalog gives a basic component
// is one the basic catalog of A2UI v0.9.1 defines for it (testdata/a2ui-v0_9_1-basic-catalog.json,
// copied from google/A2UI), and every prop that catalog requires, the node's requires too.
func TestTheCatalogIsA2UIsBasicCatalogNarrowed(t *testing.T) {
	raw, err := os.ReadFile("testdata/a2ui-v0_9_1-basic-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var basic struct {
		Components map[string]struct {
			AllOf []struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"allOf"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &basic); err != nil {
		t.Fatal(err)
	}
	for _, c := range catalog {
		def, ok := basic.Components[c.name]
		if c.own {
			if ok {
				t.Errorf("%s is the basic catalog's, not the node's own", c.name)
			}
			continue
		}
		if !ok {
			t.Errorf("%s is not in A2UI's basic catalog: mark it the node's own", c.name)
			continue
		}
		props, required := map[string]bool{}, []string{}
		for _, part := range def.AllOf {
			for k := range part.Properties {
				props[k] = true
			}
			required = append(required, part.Required...)
		}
		mine := map[string]bool{"component": true}
		for _, p := range c.props {
			if !props[p.name] {
				t.Errorf("%s.%s is not a property A2UI gives %s", c.name, p.name, c.name)
			}
			if p.required {
				mine[p.name] = true
			}
		}
		for _, r := range required {
			if !mine[r] {
				t.Errorf("A2UI requires %s.%s; the node's catalog does not", c.name, r)
			}
		}
	}
}

// An action is read against the Button it names: each literal of its context exactly as the Button
// wrote it, of the same type.
func TestAnActionReadsItsButtonsLiterals(t *testing.T) {
	sf, err := Parse([]byte(validAsks["a date and a button"]), KindAsk)
	if err != nil {
		t.Fatal(err)
	}
	for ctx, ok := range map[string]bool{
		`{"slot":"wed-15","n":1,"firm":true}`:          true,
		`{ "firm" : true, "n" : 1.0, "slot":"wed-15"}`: true,
		`{"slot":"thu-10","n":1,"firm":true}`:          false,
		`{"slot":"wed-15","n":"1","firm":true}`:        false,
		`{"slot":"wed-15","n":1,"firm":"true"}`:        false,
		`{"slot":"wed-15","n":1}`:                      false,
	} {
		if _, err := sf.ReadAction(act("approve", "ok", ctx)); (err == nil) != ok {
			t.Errorf("context %s: %v, want accepted %v", ctx, err, ok)
		}
	}
}

// a2uiMessage is A2UI v0.9.1's own server-to-client message schema (testdata, copied from
// google/A2UI), its catalog the node's: the basic catalog with the node's KeyValue added, as A2UI's
// custom catalogs are made. Two changes are made to A2UI's documents so that jsonschema-go reads
// them, neither to what they accept: the catalog's components and functions move under $defs (the
// library follows a $ref only into schema keywords), and DateTimeInput's min and max lose their
// oneOf of three formats (the library does not assert format, so all three match any string and
// the oneOf refuses every value; the node's isISO holds those).
func a2uiMessage(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	parse := func(b []byte) *jsonschema.Schema {
		var s jsonschema.Schema
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return &s
	}
	src := strings.NewReplacer(`"#/components/`, `"#/$defs/`, `"#/functions/`, `"#/$defs/`).Replace(string(read("a2ui-v0_9_1-basic-catalog.json")))
	var cat map[string]json.RawMessage
	if err := json.Unmarshal([]byte(src), &cat); err != nil {
		t.Fatal(err)
	}
	defs := map[string]any{}
	for _, part := range []string{"$defs", "components", "functions"} {
		var m map[string]any
		if err := json.Unmarshal(cat[part], &m); err != nil {
			t.Fatal(part, err)
		}
		for k, v := range m {
			defs[k] = v
		}
	}
	dti := defs["DateTimeInput"].(map[string]any)["allOf"].([]any)
	own := dti[len(dti)-1].(map[string]any)["properties"].(map[string]any)
	for _, bound := range []string{"min", "max"} {
		own[bound] = map[string]any{"$ref": "https://a2ui.org/specification/v0_9/common_types.json#/$defs/DynamicString"}
	}
	// The node's KeyValue, as the node's schema has it, its id A2UI's ComponentId.
	kv, _ := json.Marshal(Defs(KindAsk)["KeyValue"])
	var keyValue any
	_ = json.Unmarshal([]byte(strings.ReplaceAll(string(kv), `"#/$defs/ComponentId"`, `"https://a2ui.org/specification/v0_9/common_types.json#/$defs/ComponentId"`)), &keyValue)
	defs["KeyValue"] = keyValue
	anyOf := defs["anyComponent"].(map[string]any)
	anyOf["oneOf"] = append(anyOf["oneOf"].([]any), map[string]any{"$ref": "#/$defs/KeyValue"})
	delete(cat, "components")
	delete(cat, "functions")
	cat["$defs"], _ = json.Marshal(defs)
	catalogDoc, _ := json.Marshal(cat)
	catalog, common := parse(catalogDoc), parse(read("a2ui-v0_9_1-common_types.json"))
	r, err := parse(read("a2ui-v0_9_1-server_to_client.json")).Resolve(&jsonschema.ResolveOptions{Loader: func(u *url.URL) (*jsonschema.Schema, error) {
		switch u.String() {
		case "https://a2ui.org/specification/v0_9/catalog.json":
			return catalog, nil
		case "https://a2ui.org/specification/v0_9/common_types.json":
			return common, nil
		}
		return nil, fmt.Errorf("no schema %s here", u)
	}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Every surface the node takes is A2UI by A2UI's own schema: each of its messages validates as a
// v0.9.1 server-to-client message in the node's catalog. The control: A2UI's schema refuses what the
// node refuses for its shape, so the validator was reached.
func TestEverySurfaceTheNodeTakesIsA2UIByA2UIsOwnSchema(t *testing.T) {
	r := a2uiMessage(t)
	for kind, corpus := range map[string]map[string]string{KindAsk: validAsks, KindNotice: validNotices} {
		for name, s := range corpus {
			var msgs []any
			if err := json.Unmarshal([]byte(s), &msgs); err != nil {
				t.Fatal(err)
			}
			for i, m := range msgs {
				if err := r.Validate(m); err != nil {
					t.Errorf("%s %q, message %d: A2UI's schema refuses it: %v", kind, name, i, err)
				}
			}
		}
	}
	for _, name := range []string{"an unknown prop", "an option with no value", "a TextField with no label", "the old rows"} {
		var msgs []any
		_ = json.Unmarshal([]byte(invalidSurfaces[name].surface), &msgs)
		if err := r.Validate(msgs[1]); err == nil {
			t.Errorf("%q: A2UI's schema takes it", name)
		}
	}
}
