package asks

// The node's A2UI catalog: the components an agent may compose an ask or a notice from, written once.
// Schema (the owner MCP tools' input schema) and Parse (what the node stores) are both read from
// the table below, so the two cannot name different components or props. A2UI v0.9.1 (a2ui.org):
// a surface is a createSurface message and an updateComponents message, its components a flat list
// in which one, id "root", is a Column whose children are laid out top to bottom.
//
// What a JSON Schema cannot say about a list of components, Parse alone holds; codeOnlyRules names
// each of them, and catalog_test.go holds that every surface Parse accepts the schema accepts too.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
)

// Version is the A2UI version every message of a surface names.
const Version = "v0.9.1"

// CatalogID names this catalog in a surface's createSurface. It is an identifier, as A2UI's
// catalogId is, and need not resolve.
const CatalogID = "https://hdtp.dev/a2ui/v0.9.1/owner-catalog.json"

// The bounds of a surface, in bytes as read: rule 11.
const (
	// MaxSurfaceBytes is the most a surface's JSON may be; more is too_large.
	MaxSurfaceBytes = 16 << 10
	// MaxComponents is the most components one surface holds, root included.
	MaxComponents = 20
	// MaxTLDRBytes is the most the TLDR, the first Text under root, may be.
	MaxTLDRBytes = 280
	// MaxOptions is the most ready replies a Choice offers.
	MaxOptions = 3
	// MaxRows is the most rows a KeyValue holds.
	MaxRows         = 8
	maxIDBytes      = 64
	maxTextBytes    = 2000
	maxLabelBytes   = 280
	maxKeyBytes     = 64
	maxContextKeys  = 8
	maxISOBytes     = 40
	maxContextBytes = 280
)

// The kinds of what a surface is for.
const (
	KindAsk    = "ask"
	KindNotice = "notice"
)

// A prop's kind: what its value must be.
type propKind int

const (
	textProp    propKind = iota // a string of at most max bytes
	enumProp                    // one of enum
	idProp                      // a component id
	idsProp                     // a list of component ids, at most max
	rowsProp                    // [{label, value}], 1..max
	optionsProp                 // [{label}], 1..max
	boolProp                    // true or false
	actionProp                  // {event: {name, context?}}, the context's values literal
)

type prop struct {
	name     string
	kind     propKind
	required bool
	max      int
	enum     []string
	about    string
}

type component struct {
	name  string
	about string
	props []prop
	// interactive says it answers an ask: an ask needs one, and a notice may hold none.
	interactive bool
}

// catalog is every component, in the order the schema lists them.
var catalog = []component{
	{name: "Column", about: "The root, and only the root (id \"root\"): its children, top to bottom. The first is a Text, the TLDR; a TextField, if there is one, is last.",
		props: []prop{{name: "children", kind: idsProp, required: true, max: MaxComponents - 1, about: "The ids of the components under the root, in order."}}},
	{name: "Text", about: "A line of text. The first child of root is the TLDR: what the owner needs to know, in at most " + strconv.Itoa(MaxTLDRBytes) + " bytes.",
		props: []prop{
			{name: "text", kind: textProp, required: true, max: maxTextBytes},
			{name: "variant", kind: enumProp, enum: []string{"h1", "h2", "h3", "h4", "h5", "caption", "body"}},
		}},
	{name: "KeyValue", about: "The key terms, one label and value per row.",
		props: []prop{{name: "rows", kind: rowsProp, required: true, max: MaxRows}}},
	{name: "Choice", interactive: true, about: "Ready replies: choosing one sends its label to the contact as the owner's own message.",
		props: []prop{
			{name: "label", kind: textProp, max: maxLabelBytes, about: "What the choice is about."},
			{name: "options", kind: optionsProp, required: true, max: MaxOptions},
		}},
	{name: "TextField", interactive: true, about: "Write my own: what the owner types is sent to the contact as their own message. Always last.",
		props: []prop{
			{name: "label", kind: textProp, max: maxLabelBytes},
			{name: "variant", kind: enumProp, enum: []string{"shortText", "longText"}},
		}},
	{name: "DateTimeInput", interactive: true, about: "A date, a time or both, picked by the owner; it answers the ask and sends nothing.",
		props: []prop{
			{name: "label", kind: textProp, max: maxLabelBytes},
			{name: "enableDate", kind: boolProp},
			{name: "enableTime", kind: boolProp},
			{name: "min", kind: textProp, max: maxISOBytes, about: "ISO 8601."},
			{name: "max", kind: textProp, max: maxISOBytes, about: "ISO 8601."},
		}},
	{name: "Button", interactive: true, about: "A button whose label is a Text (child); pressing it answers the ask and sends nothing.",
		props: []prop{
			{name: "child", kind: idProp, required: true, about: "The id of the Text that is its label."},
			{name: "variant", kind: enumProp, enum: []string{"default", "primary", "borderless"}},
			{name: "action", kind: actionProp, required: true},
		}},
}

// codeOnlyRules are what Parse holds that the schema does not: rules over the list of components,
// not over one of them. Each is a sentence Parse refuses with; catalog_test.go shows each red.
var codeOnlyRules = []string{
	"the two messages name one surfaceId",
	"component ids are unique",
	"one component is root, and it is the only Column",
	"every component but root is placed once: under root, or as a Button's label",
	"the first child of root is a Text, the TLDR, of at most MaxTLDRBytes",
	"a TextField is the last child of root",
	"at most one Choice and one TextField",
	"an ask holds a component that answers it",
	"a Button's child is a Text",
	"a DateTimeInput enables a date, a time or both, and its min and max read as ISO 8601",
	"lengths are bytes, not characters",
}

func componentNamed(name string) (component, bool) {
	for _, c := range catalog {
		if c.name == name {
			return c, true
		}
	}
	return component{}, false
}

// allowedIn says whether a component may be part of a surface of kind: a notice tells, and holds
// nothing that answers.
func (c component) allowedIn(kind string) bool { return kind == KindAsk || !c.interactive }

// Schema is the JSON Schema of a surface of kind: the `surface` argument of ask_owner (KindAsk) and
// notify_owner (KindNotice).
func Schema(kind string) *jsonschema.Schema {
	var comps []*jsonschema.Schema
	for _, c := range catalog {
		if c.allowedIn(kind) {
			comps = append(comps, componentSchema(c))
		}
	}
	str := func(max int) *jsonschema.Schema {
		return &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(max)}
	}
	// A schema is a tree: each place gets its own node.
	version := func() *jsonschema.Schema { return &jsonschema.Schema{Type: "string", Const: anyPtr(Version)} }
	create := &jsonschema.Schema{Type: "object", Required: []string{"version", "createSurface"}, AdditionalProperties: falseSchema(),
		Properties: map[string]*jsonschema.Schema{
			"version": version(),
			"createSurface": {Type: "object", Required: []string{"surfaceId", "catalogId"}, AdditionalProperties: falseSchema(),
				Properties: map[string]*jsonschema.Schema{
					"surfaceId": str(maxIDBytes),
					"catalogId": {Type: "string", Const: anyPtr(CatalogID)},
				}},
		}}
	update := &jsonschema.Schema{Type: "object", Required: []string{"version", "updateComponents"}, AdditionalProperties: falseSchema(),
		Properties: map[string]*jsonschema.Schema{
			"version": version(),
			"updateComponents": {Type: "object", Required: []string{"surfaceId", "components"}, AdditionalProperties: falseSchema(),
				Properties: map[string]*jsonschema.Schema{
					"surfaceId":  str(maxIDBytes),
					"components": {Type: "array", MinItems: ptr(2), MaxItems: ptr(MaxComponents), Items: &jsonschema.Schema{OneOf: comps}},
				}},
		}}
	what := "An A2UI " + Version + " surface: a createSurface message naming catalogId " + CatalogID +
		", then an updateComponents message for the same surfaceId. One component has id \"root\", a Column."
	if kind == KindAsk {
		what += " An ask holds at least one of Choice, TextField, DateTimeInput or Button."
	} else {
		what += " A notice holds only Text and KeyValue: it tells, and nothing answers it."
	}
	return &jsonschema.Schema{Type: "array", Description: what, MinItems: ptr(2), MaxItems: ptr(2),
		PrefixItems: []*jsonschema.Schema{create, update}}
}

func componentSchema(c component) *jsonschema.Schema {
	props := map[string]*jsonschema.Schema{
		"id":        {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxIDBytes)},
		"component": {Type: "string", Const: anyPtr(c.name)},
	}
	order := []string{"id", "component"}
	required := []string{"id", "component"}
	for _, p := range c.props {
		props[p.name] = propSchema(p)
		order = append(order, p.name)
		if p.required {
			required = append(required, p.name)
		}
	}
	return &jsonschema.Schema{Type: "object", Description: c.about, Required: required, Properties: props,
		PropertyOrder: order, AdditionalProperties: falseSchema()}
}

func propSchema(p prop) *jsonschema.Schema {
	var s *jsonschema.Schema
	switch p.kind {
	case textProp:
		s = &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(p.max)}
	case enumProp:
		e := make([]any, len(p.enum))
		for i, v := range p.enum {
			e[i] = v
		}
		s = &jsonschema.Schema{Type: "string", Enum: e}
	case idProp:
		s = &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(maxIDBytes)}
	case idsProp:
		s = &jsonschema.Schema{Type: "array", MinItems: ptr(1), MaxItems: ptr(p.max), UniqueItems: true,
			Items: &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(maxIDBytes)}}
	case rowsProp:
		s = &jsonschema.Schema{Type: "array", MinItems: ptr(1), MaxItems: ptr(p.max), Items: &jsonschema.Schema{
			Type: "object", Required: []string{"label", "value"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"label": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxKeyBytes)},
				"value": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxLabelBytes)},
			}}}
	case optionsProp:
		s = &jsonschema.Schema{Type: "array", MinItems: ptr(1), MaxItems: ptr(p.max), Items: &jsonschema.Schema{
			Type: "object", Required: []string{"label"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"label": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxLabelBytes), Description: "The reply itself, as it is sent."},
			}}}
	case boolProp:
		s = &jsonschema.Schema{Type: "boolean"}
	case actionProp:
		literal := &jsonschema.Schema{Types: []string{"string", "number", "boolean"}}
		s = &jsonschema.Schema{Type: "object", Required: []string{"event"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"event": {Type: "object", Required: []string{"name"}, AdditionalProperties: falseSchema(),
					Properties: map[string]*jsonschema.Schema{
						"name":    {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxKeyBytes)},
						"context": {Type: "object", MaxProperties: ptr(maxContextKeys), AdditionalProperties: literal},
					}},
			}}
	}
	s.Description = p.about
	return s
}

func ptr(n int) *int                  { return &n }
func anyPtr(v any) *any               { return &v }
func falseSchema() *jsonschema.Schema { return &jsonschema.Schema{Not: &jsonschema.Schema{}} }

// Surface is a surface Parse accepted: its id and its components, root first.
type Surface struct {
	ID         string
	Components []Component
}

// Component is one component of a surface, with the props its kind may carry.
type Component struct {
	ID         string   `json:"id"`
	Name       string   `json:"component"`
	Children   []string `json:"children,omitempty"`
	Text       string   `json:"text,omitempty"`
	Variant    string   `json:"variant,omitempty"`
	Label      string   `json:"label,omitempty"`
	Rows       []Row    `json:"rows,omitempty"`
	Options    []Option `json:"options,omitempty"`
	EnableDate bool     `json:"enableDate,omitempty"`
	EnableTime bool     `json:"enableTime,omitempty"`
	Min        string   `json:"min,omitempty"`
	Max        string   `json:"max,omitempty"`
	Child      string   `json:"child,omitempty"`
	Action     *Action  `json:"action,omitempty"`
}

// Row is one row of a KeyValue.
type Row struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Option is one ready reply of a Choice: its label is the reply.
type Option struct {
	Label string `json:"label"`
}

// Action is a Button's: the event it names and its literal context.
type Action struct {
	Event struct {
		Name    string                     `json:"name"`
		Context map[string]json.RawMessage `json:"context,omitempty"`
	} `json:"event"`
}

// Find returns the component with id, if the surface has it.
func (s Surface) Find(id string) (Component, bool) {
	for _, c := range s.Components {
		if c.ID == id {
			return c, true
		}
	}
	return Component{}, false
}

// TLDR is the first Text under root.
func (s Surface) TLDR() string {
	root, _ := s.Find("root")
	if len(root.Children) == 0 {
		return ""
	}
	t, _ := s.Find(root.Children[0])
	return t.Text
}

// Invalid is a surface Parse refused: Path is where, in A2UI's JSON Pointer form under the tool's
// `surface` argument, and TooLarge says the refusal is for its size.
type Invalid struct {
	Path, Why string
	TooLarge  bool
}

func (e Invalid) Error() string {
	if e.Path == "" {
		return e.Why
	}
	return e.Path + ": " + e.Why
}

func invalid(path, format string, args ...any) error {
	return Invalid{Path: path, Why: fmt.Sprintf(format, args...)}
}

// Parse reads raw, the `surface` argument, as a surface of kind, and refuses anything the catalog
// does not allow. The bytes counted are raw's own.
func Parse(raw []byte, kind string) (Surface, error) {
	if len(raw) > MaxSurfaceBytes {
		return Surface{}, Invalid{Path: "/surface", Why: fmt.Sprintf("the surface is %d bytes, over the %d a surface may be", len(raw), MaxSurfaceBytes), TooLarge: true}
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return Surface{}, invalid("/surface", "not a list of A2UI messages")
	}
	if len(msgs) != 2 {
		return Surface{}, invalid("/surface", "a surface is two messages, createSurface then updateComponents; this is %d", len(msgs))
	}
	var create struct {
		SurfaceID string `json:"surfaceId"`
		CatalogID string `json:"catalogId"`
	}
	if err := message(msgs[0], "/surface/0", "createSurface", &create, "surfaceId", "catalogId"); err != nil {
		return Surface{}, err
	}
	if create.CatalogID != CatalogID {
		return Surface{}, invalid("/surface/0/createSurface/catalogId", "the catalog is %s", CatalogID)
	}
	if err := checkID("/surface/0/createSurface/surfaceId", create.SurfaceID); err != nil {
		return Surface{}, err
	}
	var update struct {
		SurfaceID  string            `json:"surfaceId"`
		Components []json.RawMessage `json:"components"`
	}
	if err := message(msgs[1], "/surface/1", "updateComponents", &update, "surfaceId", "components"); err != nil {
		return Surface{}, err
	}
	if update.SurfaceID != create.SurfaceID {
		return Surface{}, invalid("/surface/1/updateComponents/surfaceId", "names surface %q; the createSurface made %q", update.SurfaceID, create.SurfaceID)
	}
	base := "/surface/1/updateComponents/components"
	if len(update.Components) < 2 || len(update.Components) > MaxComponents {
		return Surface{}, invalid(base, "a surface holds 2 to %d components; this has %d", MaxComponents, len(update.Components))
	}
	s := Surface{ID: create.SurfaceID}
	at := map[string]int{}
	for i, rc := range update.Components {
		c, err := parseComponent(rc, kind, fmt.Sprintf("%s/%d", base, i))
		if err != nil {
			return Surface{}, err
		}
		if _, dup := at[c.ID]; dup {
			return Surface{}, invalid(fmt.Sprintf("%s/%d/id", base, i), "id %q is used twice", c.ID)
		}
		at[c.ID] = i
		s.Components = append(s.Components, c)
	}
	if err := s.checkTree(kind, base, at); err != nil {
		return Surface{}, err
	}
	// Root first: what a reader of the stored surface meets first.
	r := at["root"]
	s.Components[0], s.Components[r] = s.Components[r], s.Components[0]
	return s, nil
}

// message reads one A2UI message: version, and the one body named name with exactly the keys keys.
func message(m map[string]json.RawMessage, path, name string, into any, keys ...string) error {
	var v string
	if err := json.Unmarshal(m["version"], &v); err != nil || v != Version {
		return invalid(path+"/version", "every message names version %s", Version)
	}
	body, ok := m[name]
	if !ok || len(m) != 2 {
		return invalid(path, "this message is %s, and holds version and %s alone", name, name)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return invalid(path+"/"+name, "not an object")
	}
	for k := range fields {
		if !contains(keys, k) {
			return invalid(path+"/"+name+"/"+k, "%s takes %s, and nothing else", name, strings.Join(keys, " and "))
		}
	}
	for _, k := range keys {
		if _, ok := fields[k]; !ok {
			return invalid(path+"/"+name+"/"+k, "required")
		}
	}
	if err := json.Unmarshal(body, into); err != nil {
		return invalid(path+"/"+name, "a field is of the wrong type")
	}
	return nil
}

func parseComponent(raw json.RawMessage, kind, path string) (Component, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Component{}, invalid(path, "a component is an object")
	}
	var name, id string
	if json.Unmarshal(fields["component"], &name) != nil || name == "" {
		return Component{}, invalid(path+"/component", "required: one of %s", names(kind))
	}
	spec, ok := componentNamed(name)
	if !ok || !spec.allowedIn(kind) {
		return Component{}, invalid(path+"/component", "%q is not in the catalog for a%s %s: it takes %s", name, an(kind), kind, names(kind))
	}
	if json.Unmarshal(fields["id"], &id) != nil {
		return Component{}, invalid(path+"/id", "required")
	}
	if err := checkID(path+"/id", id); err != nil {
		return Component{}, err
	}
	for k := range fields {
		if k == "id" || k == "component" {
			continue
		}
		if _, ok := spec.prop(k); !ok {
			return Component{}, invalid(path+"/"+k, "%s has no %q", name, k)
		}
	}
	for _, p := range spec.props {
		v, ok := fields[p.name]
		if !ok {
			if p.required {
				return Component{}, invalid(path+"/"+p.name, "required")
			}
			continue
		}
		if err := checkProp(p, v, path+"/"+p.name); err != nil {
			return Component{}, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var c Component
	if err := dec.Decode(&c); err != nil {
		return Component{}, invalid(path, "a field is of the wrong type")
	}
	if c.Name == "DateTimeInput" {
		if !c.EnableDate && !c.EnableTime {
			return Component{}, invalid(path, "a DateTimeInput enables a date, a time or both")
		}
		for _, b := range []struct{ name, v string }{{"min", c.Min}, {"max", c.Max}} {
			if b.v != "" && !isISO(b.v) {
				return Component{}, invalid(path+"/"+b.name, "not an ISO 8601 date, time or date-time")
			}
		}
	}
	return c, nil
}

func (c component) prop(name string) (prop, bool) {
	for _, p := range c.props {
		if p.name == name {
			return p, true
		}
	}
	return prop{}, false
}

func checkProp(p prop, v json.RawMessage, path string) error {
	switch p.kind {
	case textProp:
		return checkText(v, path, p.max)
	case enumProp:
		var s string
		if json.Unmarshal(v, &s) != nil || !contains(p.enum, s) {
			return invalid(path, "one of %s", strings.Join(p.enum, ", "))
		}
	case idProp:
		var s string
		if json.Unmarshal(v, &s) != nil {
			return invalid(path, "a component id")
		}
		return checkID(path, s)
	case idsProp:
		var l []string
		if json.Unmarshal(v, &l) != nil || len(l) == 0 {
			return invalid(path, "a list of component ids")
		}
		if len(l) > p.max {
			return invalid(path, "at most %d", p.max)
		}
		for i, s := range l {
			if err := checkID(fmt.Sprintf("%s/%d", path, i), s); err != nil {
				return err
			}
		}
	case rowsProp:
		var l []map[string]json.RawMessage
		if json.Unmarshal(v, &l) != nil || len(l) == 0 {
			return invalid(path, "a list of rows, each a label and a value")
		}
		if len(l) > p.max {
			return invalid(path, "at most %d rows; this has %d", p.max, len(l))
		}
		for i, r := range l {
			if err := exactKeys(r, fmt.Sprintf("%s/%d", path, i), "label", "value"); err != nil {
				return err
			}
			if err := checkText(r["label"], fmt.Sprintf("%s/%d/label", path, i), maxKeyBytes); err != nil {
				return err
			}
			if err := checkText(r["value"], fmt.Sprintf("%s/%d/value", path, i), maxLabelBytes); err != nil {
				return err
			}
		}
	case optionsProp:
		var l []map[string]json.RawMessage
		if json.Unmarshal(v, &l) != nil || len(l) == 0 {
			return invalid(path, "a list of ready replies, each a label")
		}
		if len(l) > p.max {
			return invalid(path, "at most %d ready replies; this has %d", p.max, len(l))
		}
		for i, o := range l {
			if err := exactKeys(o, fmt.Sprintf("%s/%d", path, i), "label"); err != nil {
				return err
			}
			if err := checkText(o["label"], fmt.Sprintf("%s/%d/label", path, i), maxLabelBytes); err != nil {
				return err
			}
		}
	case boolProp:
		var b bool
		if json.Unmarshal(v, &b) != nil {
			return invalid(path, "true or false")
		}
	case actionProp:
		var a map[string]json.RawMessage
		if json.Unmarshal(v, &a) != nil {
			return invalid(path, "an action: {event: {name, context}}")
		}
		if err := exactKeys(a, path, "event"); err != nil {
			return err
		}
		var ev map[string]json.RawMessage
		if json.Unmarshal(a["event"], &ev) != nil {
			return invalid(path+"/event", "an event: {name, context}")
		}
		for k := range ev {
			if k != "name" && k != "context" {
				return invalid(path+"/event/"+k, "an event has a name and a context, and nothing else")
			}
		}
		var name string
		if json.Unmarshal(ev["name"], &name) != nil || name == "" || len(name) > maxKeyBytes {
			return invalid(path+"/event/name", "a name of 1 to %d bytes", maxKeyBytes)
		}
		if c, ok := ev["context"]; ok {
			var ctx map[string]json.RawMessage
			if json.Unmarshal(c, &ctx) != nil {
				return invalid(path+"/event/context", "an object")
			}
			if len(ctx) > maxContextKeys {
				return invalid(path+"/event/context", "at most %d keys", maxContextKeys)
			}
			for k, cv := range ctx {
				var lit any
				if json.Unmarshal(cv, &lit) != nil {
					return invalid(path+"/event/context/"+k, "a literal")
				}
				switch x := lit.(type) {
				case string:
					if len(x) > maxContextBytes {
						return invalid(path+"/event/context/"+k, "at most %d bytes", maxContextBytes)
					}
				case float64, bool:
				default:
					return invalid(path+"/event/context/"+k, "a literal string, number or boolean: the node binds no data model")
				}
			}
		}
	}
	return nil
}

func exactKeys(m map[string]json.RawMessage, path string, keys ...string) error {
	for k := range m {
		if !contains(keys, k) {
			return invalid(path+"/"+k, "takes %s, and nothing else", strings.Join(keys, " and "))
		}
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return invalid(path+"/"+k, "required")
		}
	}
	return nil
}

func checkText(v json.RawMessage, path string, max int) error {
	var s string
	if json.Unmarshal(v, &s) != nil {
		return invalid(path, "a string")
	}
	if strings.TrimSpace(s) == "" {
		return invalid(path, "empty")
	}
	if len(s) > max {
		return invalid(path, "%d bytes, over the %d it may be", len(s), max)
	}
	if !utf8.ValidString(s) {
		return invalid(path, "not UTF-8")
	}
	return nil
}

func checkID(path, id string) error {
	if id == "" || len(id) > maxIDBytes {
		return invalid(path, "an id of 1 to %d bytes", maxIDBytes)
	}
	return nil
}

// checkTree holds the rules over the list: codeOnlyRules.
func (s Surface) checkTree(kind, base string, at map[string]int) error {
	r, ok := at["root"]
	if !ok {
		return invalid(base, "no component has id \"root\"")
	}
	root := s.Components[r]
	if root.Name != "Column" {
		return invalid(fmt.Sprintf("%s/%d/component", base, r), "root is a Column")
	}
	placed := map[string]bool{}
	place := func(path, id string) error {
		if id == "root" {
			return invalid(path, "root is placed under nothing")
		}
		if _, ok := at[id]; !ok {
			return invalid(path, "no component has id %q", id)
		}
		if placed[id] {
			return invalid(path, "component %q is placed twice", id)
		}
		placed[id] = true
		return nil
	}
	cpath := fmt.Sprintf("%s/%d/children", base, r)
	for i, id := range root.Children {
		if err := place(fmt.Sprintf("%s/%d", cpath, i), id); err != nil {
			return err
		}
	}
	choices, fields, answers := 0, 0, 0
	for i, c := range s.Components {
		path := fmt.Sprintf("%s/%d", base, i)
		switch c.Name {
		case "Column":
			if c.ID != "root" {
				return invalid(path+"/component", "a Column is the root alone")
			}
		case "Button":
			if err := place(path+"/child", c.Child); err != nil {
				return err
			}
			if s.Components[at[c.Child]].Name != "Text" {
				return invalid(path+"/child", "a Button's child is the Text that is its label")
			}
		case "Choice":
			choices++
		case "TextField":
			fields++
		}
		if spec, _ := componentNamed(c.Name); spec.interactive {
			answers++
		}
	}
	for i, c := range s.Components {
		if c.ID != "root" && !placed[c.ID] {
			return invalid(fmt.Sprintf("%s/%d", base, i), "component %q is placed nowhere: under root, or as a Button's label", c.ID)
		}
	}
	first := s.Components[at[root.Children[0]]]
	if first.Name != "Text" {
		return invalid(cpath+"/0", "the first child of root is a Text, the TLDR")
	}
	if len(first.Text) > MaxTLDRBytes {
		return invalid(fmt.Sprintf("%s/%d/text", base, at[first.ID]), "the TLDR is %d bytes, over the %d it may be", len(first.Text), MaxTLDRBytes)
	}
	if choices > 1 || fields > 1 {
		return invalid(base, "at most one Choice and one TextField")
	}
	for i, id := range root.Children {
		if s.Components[at[id]].Name == "TextField" && i != len(root.Children)-1 {
			return invalid(fmt.Sprintf("%s/%d", cpath, i), "the TextField is the last child of root")
		}
	}
	if kind == KindAsk && answers == 0 {
		return invalid(base, "an ask holds a Choice, a TextField, a DateTimeInput or a Button: something that answers it")
	}
	return nil
}

func isISO(v string) bool {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02", "15:04", "15:04:05"} {
		if _, err := time.Parse(layout, v); err == nil {
			return true
		}
	}
	return false
}

func names(kind string) string {
	var out []string
	for _, c := range catalog {
		if c.allowedIn(kind) {
			out = append(out, c.name)
		}
	}
	return strings.Join(out, ", ")
}

func an(kind string) string {
	if kind == KindAsk {
		return "n"
	}
	return ""
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
