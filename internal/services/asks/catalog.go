package asks

// The node's A2UI catalog: the components an agent may compose an ask or a notice from, written once.
// Schema (the owner MCP tools' input schema) and Parse (what the node stores) are both read from
// the table below, so the two cannot name different components or props.
//
// A2UI v0.9.1 (google/A2UI, specification/v0_9_1): a surface is a createSurface message naming its
// catalog, an updateComponents message whose components are a flat list in which one, id "root", is
// the root, and optionally an updateDataModel message with the values its inputs start from. The
// catalog is the node's own, as A2UI provides for, named by CatalogID: six of the basic catalog's
// components under their names and with their properties' shapes, narrowed to what the portal draws,
// and KeyValue, the node's own. catalog_test.go validates every surface Parse takes against A2UI's
// own message schema in a catalog of the basic components and this KeyValue. Every input binds its value to a path in the
// data model; a Button's action names the paths it sends, and pressing it is the answer (Resolve).
//
// What a JSON Schema cannot say about a list of components, Parse alone holds; the code-only rules below the catalog name
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
const CatalogID = "https://hdtp.dev/a2ui/v0_9_1/catalogs/owner/catalog.json"

// The bounds of a surface, in bytes as read: rule 11.
const (
	// MaxSurfaceBytes is the most a surface's JSON may be; more is too_large.
	MaxSurfaceBytes = 16 << 10
	// MaxComponents is the most components one surface holds, root included.
	MaxComponents = 20
	// MaxTLDRBytes is the most the TLDR, the first Text under root, may be.
	MaxTLDRBytes = 280
	// MaxOptions is the most ready replies an ask offers: its reply Buttons, and a ChoicePicker's
	// options.
	MaxOptions = 3
	// MaxItems is the most items a KeyValue holds.
	MaxItems = 8
	// MaxModelDepth is how deeply the data model's value may nest, its object counted as 1.
	MaxModelDepth   = 4
	maxIDBytes      = 64
	maxTextBytes    = 2000
	maxLabelBytes   = 280
	maxKeyBytes     = 64
	maxContextKeys  = 8
	maxISOBytes     = 40
	maxContextBytes = 280
	maxPathBytes    = 64
)

// ReplyEvent names a ready reply's Button: its context is {reply}, the reply's text, and one tap on
// it sends that text to the contact as the owner's own message.
const ReplyEvent = "reply"

// PlacedOnce is where each component goes, as checkTree holds it (placed_twice, placed_nowhere,
// root_placed, button_label), in the words the schema, the Column, the Button and ask_owner give it.
const PlacedOnce = "Every component but root is placed exactly once: listed in root's children, or named as a Button's child, its label. " +
	"Each Button, the Send too, has a label Text of its own as its child, and root's children do not list that Text."

// The kinds of what a surface is for.
const (
	KindAsk    = "ask"
	KindNotice = "notice"
)

// A prop's kind: what its value must be.
type propKind int

const (
	textProp     propKind = iota // a literal string of at most max bytes
	enumProp                     // one of enum
	idProp                       // a component id (A2UI's ComponentId)
	childrenProp                 // a list of component ids, at most max (A2UI's ChildList, as an array)
	itemsProp                    // [{label, value}], 1..max: KeyValue's
	optionsProp                  // [{label, value}], 1..max, values distinct: ChoicePicker's
	boolProp                     // true or false
	isoProp                      // an ISO 8601 date, time or date-time, literal
	bindingProp                  // {path}: A2UI's DataBinding, an absolute JSON Pointer
	actionProp                   // {event: {name, context?}}, the context's values literals or bindings
)

type prop struct {
	name     string
	kind     propKind
	required bool
	max      int
	enum     []string
	about    string
}

// role is what a component does on an ask.
type role int

const (
	shows   role = iota // tells: Text, KeyValue, the root
	input               // binds a value the owner sets: ChoicePicker, TextField, DateTimeInput
	answers             // sends the answer: Button
)

type component struct {
	name  string
	about string
	props []prop
	role  role
	// own says the component is the node's, not the basic catalog's.
	own bool
}

// catalog is every component, in the order the schema lists them.
var catalog = []component{
	{name: "Column", about: "The root, and only the root (id \"root\"), first in the list: its children, top to bottom. The first is a Text, the TLDR, second in the list. " + PlacedOnce,
		props: []prop{{name: "children", kind: childrenProp, required: true, max: MaxComponents - 1, about: "The ids of the components under the root, in order."}}},
	{name: "Text", about: "A line of text. The first child of root is the TLDR: what the owner needs to know, in at most " + strconv.Itoa(MaxTLDRBytes) + " bytes.",
		props: []prop{
			{name: "text", kind: textProp, required: true, max: maxTextBytes, about: "Literal text."},
			{name: "variant", kind: enumProp, enum: []string{"h1", "h2", "h3", "h4", "h5", "caption", "body"}},
		}},
	{name: "KeyValue", own: true, about: "The node's own component: the key terms, one label and value per item.",
		props: []prop{{name: "items", kind: itemsProp, required: true, max: MaxItems}}},
	{name: "ChoicePicker", role: input, about: "Options the owner picks one of: its value is written at the bound path, and a Button whose context reads that path sends the picked option's label to the contact as the owner's own message. Ready replies are reply Buttons instead: one tap each.",
		props: []prop{
			{name: "label", kind: textProp, max: maxLabelBytes, about: "What the choice is about."},
			{name: "variant", kind: enumProp, enum: []string{"mutuallyExclusive"}},
			{name: "options", kind: optionsProp, required: true, max: MaxOptions},
			{name: "value", kind: bindingProp, required: true, about: "Where the chosen value is written: a list of at most one option's value."},
		}},
	{name: "TextField", role: input, about: "Write my own: what the owner types is written at the bound path. Every ask has one, root's next-to-last child, and root's last child is the Button that sends it: its context reads this path, and what the owner wrote is sent to the contact as their own message.",
		props: []prop{
			{name: "label", kind: textProp, required: true, max: maxLabelBytes},
			{name: "value", kind: bindingProp, required: true},
			{name: "variant", kind: enumProp, enum: []string{"shortText", "longText"}},
		}},
	{name: "DateTimeInput", role: input, about: "A date, a time or both, picked by the owner and written at the bound path; a Button that sends it answers the ask and sends nothing to the contact.",
		props: []prop{
			{name: "value", kind: bindingProp, required: true},
			{name: "enableDate", kind: boolProp},
			{name: "enableTime", kind: boolProp},
			{name: "min", kind: isoProp, about: "ISO 8601."},
			{name: "max", kind: isoProp, about: "ISO 8601."},
			{name: "label", kind: textProp, max: maxLabelBytes},
		}},
	{name: "Button", role: answers, about: "A button whose label is a Text (child), never a TextField. " + PlacedOnce + " Pressing it answers the ask. A ready reply is a Button whose event is \"" + ReplyEvent + "\" and whose context is {reply: the reply's text}: one tap sends that text to the contact as the owner's own message. Any other Button answers with its context, each {path} read from the data model.",
		props: []prop{
			{name: "child", kind: idProp, required: true, about: "The id of the Text that is its label."},
			{name: "variant", kind: enumProp, enum: []string{"default", "primary", "borderless"}},
			{name: "action", kind: actionProp, required: true},
		}},
}

// The code-only rules are what Parse holds that the schema does not: rules over the list of
// components that JSON Schema cannot state, not over one of them. What it can state, the schema
// states as well: root first in the list and a Text second, at most one root and ChoicePicker, at
// most MaxOptions reply Buttons, and in every ask exactly one TextField and a Button that is not a
// reply. Each code-only rule is a
// sentence Parse refuses with; catalog_test.go shows each red:
//
//   - the messages name one surfaceId
//   - component ids are unique
//   - every component but root is placed once: under root, or as a Button's label
//   - the first child of root is the Text second in the list, the TLDR, of at most MaxTLDRBytes
//   - an ask ends with the owner's own message: root's last two children are the TextField, then
//     a Button that is not a ready reply and whose context reads the TextField's path
//   - a Button's child is a Text
//   - each input binds a path of its own, none inside another's
//   - every path a Button's context reads is one an input binds
//   - a DateTimeInput enables a date, a time or both
//   - the data model nests at most MaxModelDepth deep, and what it holds at an input's path is a
//     value that input could have written
//   - lengths are bytes, not characters

func componentNamed(name string) (component, bool) {
	for _, c := range catalog {
		if c.name == name {
			return c, true
		}
	}
	return component{}, false
}

// allowedIn says whether a component may be part of a surface of kind: a notice tells, and holds
// nothing to set and nothing that answers.
func (c component) allowedIn(kind string) bool { return kind == KindAsk || c.role == shows }

// ref is a local reference to one of Defs' schemas.
func ref(name string) *jsonschema.Schema { return &jsonschema.Schema{Ref: "#/$defs/" + name} }

// Defs are the schemas a surface of kind refers to, by local reference: A2UI's ComponentId, ChildList
// and DataBinding, and one per component. They belong at the root of the document that holds
// SurfaceSchema, as `$defs`.
func Defs(kind string) map[string]*jsonschema.Schema {
	defs := map[string]*jsonschema.Schema{
		"ComponentId": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxIDBytes)},
		"ChildList": {Type: "array", MinItems: ptr(1), MaxItems: ptr(MaxComponents - 1), UniqueItems: true,
			Items: ref("ComponentId")},
		"DataBinding": {Type: "object", Required: []string{"path"}, AdditionalProperties: falseSchema(),
			Description: "A path in the surface's data model: an absolute JSON Pointer.",
			Properties: map[string]*jsonschema.Schema{
				"path": {Type: "string", Pattern: "^/", MinLength: ptr(2), MaxLength: ptr(maxPathBytes)},
			}},
	}
	for _, c := range catalog {
		if c.allowedIn(kind) {
			defs[c.name] = componentSchema(c)
		}
	}
	return defs
}

// SurfaceSchema is the JSON Schema of a surface of kind: the `surface` argument of ask_owner
// (KindAsk) and notify_owner (KindNotice). Its references are to Defs, which the document that
// holds it carries at its root.
func SurfaceSchema(kind string) *jsonschema.Schema {
	var comps []*jsonschema.Schema
	for _, c := range catalog {
		if c.allowedIn(kind) {
			comps = append(comps, ref(c.name))
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
					"surfaceId": str(maxIDBytes),
					"components": {Type: "array", MinItems: ptr(2), MaxItems: ptr(MaxComponents),
						PrefixItems: []*jsonschema.Schema{ref("Column"), ref("Text")}, Items: &jsonschema.Schema{AnyOf: comps}, AllOf: listRules(kind)},
				}},
		}}
	what := "An A2UI " + Version + " surface: a createSurface message naming catalogId " + CatalogID +
		", then an updateComponents message for the same surfaceId. Its components list the root first, a Column of id \"root\", then the TLDR, the Text that is root's first child. " + PlacedOnce
	prefix := []*jsonschema.Schema{create, update}
	most := 2
	if kind == KindAsk {
		model := &jsonschema.Schema{Type: "object", Required: []string{"version", "updateDataModel"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"version": version(),
				"updateDataModel": {Type: "object", Required: []string{"surfaceId", "value"}, AdditionalProperties: falseSchema(),
					Properties: map[string]*jsonschema.Schema{
						"surfaceId": str(maxIDBytes),
						"path":      {Type: "string", Const: anyPtr("/"), Description: "The whole data model; omit it or give \"/\"."},
						"value":     {Type: "object", Description: "The data model the inputs start from, by their paths."},
					}},
			}}
		prefix, most = append(prefix, model), 3
		what += " Optionally a third, updateDataModel for the same surfaceId: the values the inputs start from. " +
			"The owner answers by pressing a Button. Each ready reply is a Button of event \"" + ReplyEvent + "\" with context {reply: its text}, sent in one tap; " +
			"every input binds its value to a {path}, and the Button that sends it names those paths in its context. " +
			"Every ask ends with the owner's own message: root's last two children are a TextField, then the Button that sends it, " +
			"whose context reads the TextField's path."
	} else {
		what += " A notice holds only Text and KeyValue: it tells, and nothing answers it."
	}
	return &jsonschema.Schema{Type: "array", Description: what, MinItems: ptr(2), MaxItems: ptr(most), PrefixItems: prefix}
}

// listRules are the rules over a surface's list of components that JSON Schema can state: at most
// one root, and on an ask at most one ChoicePicker, at most MaxOptions reply Buttons, exactly one
// TextField and a Button that is not a reply. Where they stand under root, and what that Button
// reads, only Parse can hold.
func listRules(kind string) []*jsonschema.Schema {
	is := func(name string) *jsonschema.Schema {
		return &jsonschema.Schema{Type: "object", Required: []string{"component"},
			Properties: map[string]*jsonschema.Schema{"component": {Const: anyPtr(name)}}}
	}
	atMost := func(of *jsonschema.Schema, n int) *jsonschema.Schema {
		return &jsonschema.Schema{Contains: of, MinContains: ptr(0), MaxContains: ptr(n)}
	}
	rules := []*jsonschema.Schema{atMost(is("Column"), 1)}
	if kind != KindAsk {
		return rules
	}
	reply := is("Button")
	reply.Required = append(reply.Required, "action")
	reply.Properties["action"] = &jsonschema.Schema{Type: "object", Required: []string{"event"},
		Properties: map[string]*jsonschema.Schema{"event": {Type: "object", Required: []string{"name"},
			Properties: map[string]*jsonschema.Schema{"name": {Const: anyPtr(ReplyEvent)}}}}}
	send := is("Button")
	send.Required = append(send.Required, "action")
	send.Properties["action"] = &jsonschema.Schema{Type: "object", Required: []string{"event"},
		Properties: map[string]*jsonschema.Schema{"event": {Type: "object", Required: []string{"name"},
			Properties: map[string]*jsonschema.Schema{"name": {Not: &jsonschema.Schema{Const: anyPtr(ReplyEvent)}}}}}}
	return append(rules, atMost(is("ChoicePicker"), 1), atMost(reply, MaxOptions),
		&jsonschema.Schema{Contains: is("TextField"), MinContains: ptr(1), MaxContains: ptr(1)},
		&jsonschema.Schema{Contains: send})
}

func componentSchema(c component) *jsonschema.Schema {
	props := map[string]*jsonschema.Schema{
		"id":        ref("ComponentId"),
		"component": {Type: "string", Const: anyPtr(c.name)},
	}
	if c.name == "Column" {
		props["id"] = &jsonschema.Schema{Type: "string", Const: anyPtr("root")}
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
	labelled := func(labelMax int) *jsonschema.Schema {
		return &jsonschema.Schema{Type: "object", Required: []string{"label", "value"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"label": {Type: "string", MinLength: ptr(1), MaxLength: ptr(labelMax)},
				"value": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxLabelBytes)},
			}}
	}
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
		s = ref("ComponentId")
	case childrenProp:
		s = ref("ChildList")
	case itemsProp:
		s = &jsonschema.Schema{Type: "array", MinItems: ptr(1), MaxItems: ptr(p.max), Items: labelled(maxKeyBytes)}
	case optionsProp:
		s = &jsonschema.Schema{Type: "array", MinItems: ptr(1), MaxItems: ptr(p.max), Items: labelled(maxLabelBytes),
			Description: "Each option's label is the reply itself, as it is sent; its value is what the data model holds when it is chosen."}
	case boolProp:
		s = &jsonschema.Schema{Type: "boolean"}
	case isoProp:
		s = &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(maxISOBytes)}
	case bindingProp:
		s = ref("DataBinding")
	case actionProp:
		value := &jsonschema.Schema{AnyOf: []*jsonschema.Schema{
			{Type: "string", MaxLength: ptr(maxContextBytes)}, {Type: "number"}, {Type: "boolean"}, ref("DataBinding"),
		}}
		reply := &jsonschema.Schema{Type: "object", Required: []string{"name", "context"}, AdditionalProperties: falseSchema(),
			Description: "A ready reply: one tap sends context.reply to the contact as the owner's own message.",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Const: anyPtr(ReplyEvent)},
				"context": {Type: "object", Required: []string{"reply"}, AdditionalProperties: falseSchema(),
					Properties: map[string]*jsonschema.Schema{"reply": {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxContextBytes)}}},
			}}
		other := &jsonschema.Schema{Type: "object", Required: []string{"name"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{
				"name":    {Type: "string", MinLength: ptr(1), MaxLength: ptr(maxKeyBytes), Not: &jsonschema.Schema{Const: anyPtr(ReplyEvent)}},
				"context": {Type: "object", MaxProperties: ptr(maxContextKeys), AdditionalProperties: value},
			}}
		s = &jsonschema.Schema{Type: "object", Required: []string{"event"}, AdditionalProperties: falseSchema(),
			Properties: map[string]*jsonschema.Schema{"event": {AnyOf: []*jsonschema.Schema{reply, other}}}}
	}
	if p.about != "" && s.Ref == "" {
		s.Description = p.about
	}
	return s
}

func ptr(n int) *int                  { return &n }
func anyPtr(v any) *any               { return &v }
func falseSchema() *jsonschema.Schema { return &jsonschema.Schema{Not: &jsonschema.Schema{}} }

// Surface is a surface Parse accepted: its id, its components, root first, and its data model.
type Surface struct {
	ID         string
	Components []Component
	// Model is the data model the inputs start from; nil when the surface sent none.
	Model map[string]any
}

// Component is one component of a surface, with the props its kind may carry.
type Component struct {
	ID         string   `json:"id"`
	Name       string   `json:"component"`
	Children   []string `json:"children,omitempty"`
	Text       string   `json:"text,omitempty"`
	Variant    string   `json:"variant,omitempty"`
	Label      string   `json:"label,omitempty"`
	Items      []Item   `json:"items,omitempty"`
	Options    []Item   `json:"options,omitempty"`
	Value      *Binding `json:"value,omitempty"`
	EnableDate bool     `json:"enableDate,omitempty"`
	EnableTime bool     `json:"enableTime,omitempty"`
	Min        string   `json:"min,omitempty"`
	Max        string   `json:"max,omitempty"`
	Child      string   `json:"child,omitempty"`
	Action     *Action  `json:"action,omitempty"`
}

// Item is one item of a KeyValue, or one option of a ChoicePicker: its label is what the owner reads
// (and, for an option, the reply that is sent), its value what the data model holds.
type Item struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Binding is A2UI's DataBinding: a path in the surface's data model.
type Binding struct {
	Path string `json:"path"`
}

// Action is a Button's: the event it names and its context, each value a literal or a Binding.
type Action struct {
	Event struct {
		Name    string                     `json:"name"`
		Context map[string]json.RawMessage `json:"context,omitempty"`
	} `json:"event"`
}

// bound reads a context value as a Binding, if it is one.
func bound(v json.RawMessage) (string, bool) {
	var b map[string]json.RawMessage
	if json.Unmarshal(v, &b) != nil {
		return "", false
	}
	var path string
	if json.Unmarshal(b["path"], &path) != nil {
		return "", false
	}
	return path, true
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

// boundTo returns the input that binds path, if one does.
func (s Surface) boundTo(path string) (Component, bool) {
	for _, c := range s.Components {
		if c.Value != nil && c.Value.Path == path {
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

// Invalid is a surface Parse refused: Rule is which rule refused it, a code of the node's own (see
// Reason); Path is where, in A2UI's JSON Pointer form under the tool's `surface` argument; and
// TooLarge says the refusal is for its size.
type Invalid struct {
	Rule, Path, Why string
	TooLarge        bool
}

// Reason is the refusal as a code, "invalid_surface:<rule>": the rule is one the node names at the
// place it refuses, never anything the caller wrote, so it can go in an audit row and a log line.
func (e Invalid) Reason() string { return "invalid_surface:" + e.Rule }

func (e Invalid) Error() string {
	if e.Path == "" {
		return e.Why
	}
	return e.Path + ": " + e.Why
}

func invalid(rule, path, format string, args ...any) error {
	return Invalid{Rule: rule, Path: path, Why: fmt.Sprintf(format, args...)}
}

// Parse reads raw, the `surface` argument, as a surface of kind, and refuses anything the catalog
// does not allow. The bytes counted are raw's own.
func Parse(raw []byte, kind string) (Surface, error) {
	if len(raw) > MaxSurfaceBytes {
		return Surface{}, Invalid{Rule: "surface_size", Path: "/surface", Why: fmt.Sprintf("the surface is %d bytes, over the %d a surface may be", len(raw), MaxSurfaceBytes), TooLarge: true}
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return Surface{}, invalid("messages", "/surface", "not a list of A2UI messages")
	}
	most := 2
	if kind == KindAsk {
		most = 3
	}
	if len(msgs) < 2 || len(msgs) > most {
		if kind == KindAsk {
			return Surface{}, invalid("messages", "/surface", "a surface is createSurface, updateComponents and optionally updateDataModel; this is %d messages", len(msgs))
		}
		return Surface{}, invalid("messages", "/surface", "a notice is two messages, createSurface then updateComponents; this is %d", len(msgs))
	}
	var create struct {
		SurfaceID string `json:"surfaceId"`
		CatalogID string `json:"catalogId"`
	}
	if err := message(msgs[0], "/surface/0", "createSurface", &create, []string{"surfaceId", "catalogId"}, nil); err != nil {
		return Surface{}, err
	}
	if create.CatalogID != CatalogID {
		return Surface{}, invalid("catalog_id", "/surface/0/createSurface/catalogId", "the catalog is %s", CatalogID)
	}
	if err := checkID("/surface/0/createSurface/surfaceId", create.SurfaceID); err != nil {
		return Surface{}, err
	}
	var update struct {
		SurfaceID  string            `json:"surfaceId"`
		Components []json.RawMessage `json:"components"`
	}
	if err := message(msgs[1], "/surface/1", "updateComponents", &update, []string{"surfaceId", "components"}, nil); err != nil {
		return Surface{}, err
	}
	if update.SurfaceID != create.SurfaceID {
		return Surface{}, invalid("surface_id", "/surface/1/updateComponents/surfaceId", "names surface %q; the createSurface made %q", update.SurfaceID, create.SurfaceID)
	}
	base := "/surface/1/updateComponents/components"
	if len(update.Components) < 2 || len(update.Components) > MaxComponents {
		return Surface{}, invalid("component_count", base, "a surface holds 2 to %d components; this has %d", MaxComponents, len(update.Components))
	}
	s := Surface{ID: create.SurfaceID}
	at := map[string]int{}
	for i, rc := range update.Components {
		c, err := parseComponent(rc, kind, fmt.Sprintf("%s/%d", base, i))
		if err != nil {
			return Surface{}, err
		}
		if _, dup := at[c.ID]; dup {
			return Surface{}, invalid("duplicate_id", fmt.Sprintf("%s/%d/id", base, i), "id %q is used twice", c.ID)
		}
		at[c.ID] = i
		s.Components = append(s.Components, c)
	}
	if err := s.checkTree(kind, base, at); err != nil {
		return Surface{}, err
	}
	if len(msgs) == 3 {
		model, err := parseModel(msgs[2], create.SurfaceID)
		if err != nil {
			return Surface{}, err
		}
		s.Model = model
		if err := s.checkModel(); err != nil {
			return Surface{}, err
		}
	}
	return s, nil
}

// message reads one A2UI message: version, and the one body named name, which holds every key of
// required and no key outside required and optional.
func message(m map[string]json.RawMessage, path, name string, into any, required, optional []string) error {
	var v string
	if err := json.Unmarshal(m["version"], &v); err != nil || v != Version {
		return invalid("version", path+"/version", "every message names version %s", Version)
	}
	body, ok := m[name]
	if !ok || len(m) != 2 {
		return invalid("message_shape", path, "this message is %s, and holds version and %s alone", name, name)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return invalid("message_shape", path+"/"+name, "not an object")
	}
	for k := range fields {
		if !contains(required, k) && !contains(optional, k) {
			return invalid("message_shape", path+"/"+name+"/"+k, "%s takes %s, and nothing else", name, strings.Join(append(append([]string{}, required...), optional...), ", "))
		}
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return invalid("message_shape", path+"/"+name+"/"+k, "required")
		}
	}
	if err := json.Unmarshal(body, into); err != nil {
		return invalid("message_shape", path+"/"+name, "a field is of the wrong type")
	}
	return nil
}

// parseModel reads the third message: the whole data model, for the surface surfaceID.
func parseModel(m map[string]json.RawMessage, surfaceID string) (map[string]any, error) {
	path := "/surface/2"
	var dm struct {
		SurfaceID string          `json:"surfaceId"`
		Path      *string         `json:"path"`
		Value     json.RawMessage `json:"value"`
	}
	if err := message(m, path, "updateDataModel", &dm, []string{"surfaceId", "value"}, []string{"path"}); err != nil {
		return nil, err
	}
	path += "/updateDataModel"
	if dm.SurfaceID != surfaceID {
		return nil, invalid("surface_id", path+"/surfaceId", "names surface %q; the createSurface made %q", dm.SurfaceID, surfaceID)
	}
	if dm.Path != nil && *dm.Path != "/" {
		return nil, invalid("model_path", path+"/path", "the node takes the whole data model: omit path, or give \"/\"")
	}
	var model map[string]any
	if err := json.Unmarshal(dm.Value, &model); err != nil || model == nil {
		return nil, invalid("model_shape", path+"/value", "the data model is an object")
	}
	if d := depth(model); d > MaxModelDepth {
		return nil, invalid("model_depth", path+"/value", "the data model nests %d deep, over the %d it may", d, MaxModelDepth)
	}
	return model, nil
}

// depth is how deeply v nests: a scalar is 0, an object or a list one more than its deepest member.
func depth(v any) int {
	d := 0
	switch x := v.(type) {
	case map[string]any:
		for _, m := range x {
			d = max(d, depth(m))
		}
		return d + 1
	case []any:
		for _, m := range x {
			d = max(d, depth(m))
		}
		return d + 1
	}
	return 0
}

// lookup reads the data model at an absolute JSON Pointer (RFC 6901), if it holds anything there.
func lookup(model map[string]any, pointer string) (any, bool) {
	var cur any = model
	for _, tok := range strings.Split(pointer, "/")[1:] {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch x := cur.(type) {
		case map[string]any:
			v, ok := x[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			cur = x[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func parseComponent(raw json.RawMessage, kind, path string) (Component, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Component{}, invalid("component_shape", path, "a component is an object")
	}
	var name, id string
	if json.Unmarshal(fields["component"], &name) != nil || name == "" {
		return Component{}, invalid("unknown_component", path+"/component", "required: one of %s", names(kind))
	}
	spec, ok := componentNamed(name)
	if !ok || !spec.allowedIn(kind) {
		return Component{}, invalid("unknown_component", path+"/component", "%q is not in the catalog for a%s %s: it takes %s", name, an(kind), kind, names(kind))
	}
	if json.Unmarshal(fields["id"], &id) != nil {
		return Component{}, invalid("component_shape", path+"/id", "required")
	}
	if err := checkID(path+"/id", id); err != nil {
		return Component{}, err
	}
	for k := range fields {
		if k == "id" || k == "component" {
			continue
		}
		if _, ok := spec.prop(k); !ok {
			return Component{}, invalid("unknown_prop", path+"/"+k, "%s has no %q in this catalog", name, k)
		}
	}
	for _, p := range spec.props {
		v, ok := fields[p.name]
		if !ok {
			if p.required {
				return Component{}, invalid("required_prop", path+"/"+p.name, "required")
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
		return Component{}, invalid("component_shape", path, "a field is of the wrong type")
	}
	if c.Name == "DateTimeInput" && !c.EnableDate && !c.EnableTime {
		return Component{}, invalid("date_enables", path, "a DateTimeInput enables a date, a time or both")
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
			return invalid("prop_value", path, "one of %s", strings.Join(p.enum, ", "))
		}
	case idProp:
		var s string
		if json.Unmarshal(v, &s) != nil {
			return invalid("prop_value", path, "a component id")
		}
		return checkID(path, s)
	case childrenProp:
		var l []string
		if json.Unmarshal(v, &l) != nil || len(l) == 0 {
			return invalid("prop_value", path, "a list of component ids")
		}
		if len(l) > p.max {
			return invalid("prop_size", path, "at most %d", p.max)
		}
		for i, s := range l {
			if err := checkID(fmt.Sprintf("%s/%d", path, i), s); err != nil {
				return err
			}
		}
	case itemsProp, optionsProp:
		what, labelMax := "items, each a label and a value", maxKeyBytes
		if p.kind == optionsProp {
			what, labelMax = "options, each a label and a value", maxLabelBytes
		}
		var l []map[string]json.RawMessage
		if json.Unmarshal(v, &l) != nil || len(l) == 0 {
			return invalid("prop_value", path, "a list of %s", what)
		}
		if len(l) > p.max {
			return invalid("prop_size", path, "at most %d %s; this has %d", p.max, strings.SplitN(what, ",", 2)[0], len(l))
		}
		values := map[string]bool{}
		for i, it := range l {
			at := fmt.Sprintf("%s/%d", path, i)
			if err := exactKeys(it, at, "label", "value"); err != nil {
				return err
			}
			if err := checkText(it["label"], at+"/label", labelMax); err != nil {
				return err
			}
			if err := checkText(it["value"], at+"/value", maxLabelBytes); err != nil {
				return err
			}
			if p.kind == optionsProp {
				var val string
				_ = json.Unmarshal(it["value"], &val)
				if values[val] {
					return invalid("option_values", at+"/value", "two options have the value %q", val)
				}
				values[val] = true
			}
		}
	case boolProp:
		var b bool
		if json.Unmarshal(v, &b) != nil {
			return invalid("prop_value", path, "true or false")
		}
	case isoProp:
		var s string
		if json.Unmarshal(v, &s) != nil || len(s) > maxISOBytes || !isISO(s) {
			return invalid("prop_value", path, "an ISO 8601 date, time or date-time")
		}
	case bindingProp:
		return checkBinding(v, path)
	case actionProp:
		var a map[string]json.RawMessage
		if json.Unmarshal(v, &a) != nil {
			return invalid("action_shape", path, "an action: {event: {name, context}}")
		}
		if err := exactKeys(a, path, "event"); err != nil {
			return invalid("action_function", path, "an action here is an event, {event: {name, context}}: the portal runs no function")
		}
		var ev map[string]json.RawMessage
		if json.Unmarshal(a["event"], &ev) != nil {
			return invalid("action_shape", path+"/event", "an event: {name, context}")
		}
		for k := range ev {
			if k != "name" && k != "context" {
				return invalid("action_shape", path+"/event/"+k, "an event has a name and a context, and nothing else")
			}
		}
		var name string
		if json.Unmarshal(ev["name"], &name) != nil || name == "" || len(name) > maxKeyBytes {
			return invalid("action_shape", path+"/event/name", "a name of 1 to %d bytes", maxKeyBytes)
		}
		if name == ReplyEvent {
			var ctx map[string]json.RawMessage
			if json.Unmarshal(ev["context"], &ctx) != nil || exactKeys(ctx, path+"/event/context", "reply") != nil {
				return invalid("reply_context", path+"/event/context", "a ready reply's context is {reply}, the text one tap sends")
			}
			return checkText(ctx["reply"], path+"/event/context/reply", maxContextBytes)
		}
		if c, ok := ev["context"]; ok {
			var ctx map[string]json.RawMessage
			if json.Unmarshal(c, &ctx) != nil {
				return invalid("context_value", path+"/event/context", "an object")
			}
			if len(ctx) > maxContextKeys {
				return invalid("context_value", path+"/event/context", "at most %d keys", maxContextKeys)
			}
			for k, cv := range ctx {
				at := path + "/event/context/" + k
				if len(k) > maxKeyBytes {
					return invalid("context_value", at, "a key of at most %d bytes", maxKeyBytes)
				}
				var lit any
				if json.Unmarshal(cv, &lit) != nil {
					return invalid("context_value", at, "a literal or a {path}")
				}
				switch x := lit.(type) {
				case string:
					if len(x) > maxContextBytes {
						return invalid("context_value", at, "at most %d bytes", maxContextBytes)
					}
				case float64, bool:
				case map[string]any:
					if err := checkBinding(cv, at); err != nil {
						return err
					}
				default:
					return invalid("context_value", at, "a literal string, number or boolean, or a {path} in the data model")
				}
			}
		}
	}
	return nil
}

// checkBinding reads v as A2UI's DataBinding: {path}, an absolute JSON Pointer.
func checkBinding(v json.RawMessage, path string) error {
	var b map[string]json.RawMessage
	if json.Unmarshal(v, &b) != nil {
		return invalid("binding", path, "a binding: {path}")
	}
	if err := exactKeys(b, path, "path"); err != nil {
		return invalid("binding", path, "a binding is {path}, and nothing else")
	}
	var p string
	if json.Unmarshal(b["path"], &p) != nil || len(p) < 2 || len(p) > maxPathBytes || p[0] != '/' {
		return invalid("binding", path+"/path", "an absolute JSON Pointer of 2 to %d bytes", maxPathBytes)
	}
	if strings.HasSuffix(p, "/") || strings.Contains(p, "//") || strings.ReplaceAll(strings.ReplaceAll(p, "~0", ""), "~1", "") != strings.ReplaceAll(p, "~", "") {
		return invalid("binding", path+"/path", "not a JSON Pointer the node reads: no empty step, and ~ only as ~0 or ~1")
	}
	return nil
}

func exactKeys(m map[string]json.RawMessage, path string, keys ...string) error {
	for k := range m {
		if !contains(keys, k) {
			return invalid("prop_value", path+"/"+k, "takes %s, and nothing else", strings.Join(keys, " and "))
		}
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return invalid("prop_value", path+"/"+k, "required")
		}
	}
	return nil
}

func checkText(v json.RawMessage, path string, max int) error {
	var s string
	if json.Unmarshal(v, &s) != nil {
		return invalid("prop_value", path, "a literal string")
	}
	if strings.TrimSpace(s) == "" {
		return invalid("prop_value", path, "empty")
	}
	if len(s) > max {
		return invalid("prop_size", path, "%d bytes, over the %d it may be", len(s), max)
	}
	if !utf8.ValidString(s) {
		return invalid("prop_value", path, "not UTF-8")
	}
	return nil
}

func checkID(path, id string) error {
	if id == "" || len(id) > maxIDBytes {
		return invalid("prop_value", path, "an id of 1 to %d bytes", maxIDBytes)
	}
	return nil
}

// checkTree holds the rules over the list: the code-only rules.
func (s Surface) checkTree(kind, base string, at map[string]int) error {
	r, ok := at["root"]
	if !ok {
		return invalid("root_missing", base, "no component has id \"root\"")
	}
	root := s.Components[r]
	if root.Name != "Column" {
		return invalid("root_column", fmt.Sprintf("%s/%d/component", base, r), "root is a Column")
	}
	if r != 0 {
		return invalid("root_first", fmt.Sprintf("%s/%d", base, r), "root comes first in the list of components")
	}
	placed := map[string]bool{}
	place := func(path, id string) error {
		if id == "root" {
			return invalid("root_placed", path, "root is placed under nothing")
		}
		if _, ok := at[id]; !ok {
			return invalid("child_missing", path, "no component has id %q", id)
		}
		if placed[id] {
			return invalid("placed_twice", path, "component %q is placed twice", id)
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
	pickers, fields, replies := 0, 0, 0
	paths := map[string]string{}
	for i, c := range s.Components {
		path := fmt.Sprintf("%s/%d", base, i)
		switch c.Name {
		case "Column":
			if c.ID != "root" {
				return invalid("column_not_root", path+"/component", "a Column is the root alone")
			}
		case "Button":
			if c.Action.Event.Name == ReplyEvent {
				replies++
			}
			if err := place(path+"/child", c.Child); err != nil {
				return err
			}
			if s.Components[at[c.Child]].Name != "Text" {
				return invalid("button_label", path+"/child", "a Button's child is the Text that is its label")
			}
		case "ChoicePicker":
			pickers++
		case "TextField":
			fields++
		}
		if c.Value != nil {
			for other, id := range paths {
				if other == c.Value.Path || strings.HasPrefix(c.Value.Path, other+"/") || strings.HasPrefix(other, c.Value.Path+"/") {
					return invalid("binding_shared", path+"/value/path", "%q and %q bind one place in the data model: each input binds its own", id, c.ID)
				}
			}
			paths[c.Value.Path] = c.ID
		}
	}
	for i, c := range s.Components {
		if c.ID != "root" && !placed[c.ID] {
			return invalid("placed_nowhere", fmt.Sprintf("%s/%d", base, i), "component %q is placed nowhere: under root, or as a Button's label", c.ID)
		}
	}
	first := s.Components[at[root.Children[0]]]
	if first.Name != "Text" {
		return invalid("tldr_first_child", cpath+"/0", "the first child of root is a Text, the TLDR")
	}
	if at[first.ID] != 1 {
		return invalid("tldr_second", fmt.Sprintf("%s/%d", base, at[first.ID]), "the TLDR, root's first child, comes second in the list, after root")
	}
	if len(first.Text) > MaxTLDRBytes {
		return invalid("tldr_size", fmt.Sprintf("%s/%d/text", base, at[first.ID]), "the TLDR is %d bytes, over the %d it may be", len(first.Text), MaxTLDRBytes)
	}
	if pickers > 1 || fields > 1 {
		return invalid("input_count", base, "at most one ChoicePicker and one TextField")
	}
	if replies > MaxOptions {
		return invalid("reply_count", base, "at most %d ready replies; this has %d", MaxOptions, replies)
	}
	if kind == KindAsk {
		if err := s.checkOwn(root, at, cpath); err != nil {
			return err
		}
	}
	for i, c := range s.Components {
		if c.Action == nil {
			continue
		}
		for k, v := range c.Action.Event.Context {
			if p, ok := bound(v); ok {
				if _, ok := paths[p]; !ok {
					return invalid("context_unbound", fmt.Sprintf("%s/%d/action/event/context/%s", base, i, k), "no input binds %q", p)
				}
			}
		}
	}
	return nil
}

// checkOwn holds an ask to its last option, the owner's own message: root's last two children are
// the TextField, then a Button whose context reads the TextField's path, so what the owner writes
// is what that Button sends. A ready reply's context is its literal text alone, so it is never that
// Button.
func (s Surface) checkOwn(root Component, at map[string]int, cpath string) error {
	n := len(root.Children)
	if n < 3 {
		return invalid("own_message", cpath, "an ask ends with the owner's own message: a TextField, then the Button that sends it")
	}
	own := s.Components[at[root.Children[n-2]]]
	if own.Name != "TextField" {
		return invalid("own_message", fmt.Sprintf("%s/%d", cpath, n-2), "an ask ends with the owner's own message: root's next-to-last child is the TextField")
	}
	send := s.Components[at[root.Children[n-1]]]
	if send.Name != "Button" {
		return invalid("own_message", fmt.Sprintf("%s/%d", cpath, n-1), "an ask ends with the owner's own message: root's last child is the Button that sends the TextField")
	}
	for _, v := range send.Action.Event.Context {
		if p, ok := bound(v); ok && p == own.Value.Path {
			return nil
		}
	}
	return invalid("own_message", fmt.Sprintf("%s/%d/action/event/context", cpath, n-1), "the last Button sends the TextField: its context reads %q", own.Value.Path)
}

// checkModel holds the data model to the inputs: what it holds at an input's path is a value that
// input could have written.
func (s Surface) checkModel() error {
	for _, c := range s.Components {
		if c.Value == nil {
			continue
		}
		v, ok := lookup(s.Model, c.Value.Path)
		if !ok {
			continue
		}
		raw, _ := json.Marshal(v)
		if _, err := s.inputValue(c, raw); err != nil {
			return invalid("model_value", "/surface/2/updateDataModel/value", "at %s: %s", c.Value.Path, err)
		}
	}
	return nil
}

// inputValue reads v as a value input c could have written at its path, in a word: a ChoicePicker's
// is a list of at most one of its options' values (the chosen option's label returned, or ""), a
// TextField's a string, a DateTimeInput's an ISO string or "" (returned as given).
func (s Surface) inputValue(c Component, v json.RawMessage) (string, error) {
	switch c.Name {
	case "ChoicePicker":
		var l []string
		if json.Unmarshal(v, &l) != nil {
			return "", fmt.Errorf("a ChoicePicker's value is a list of option values")
		}
		if len(l) > 1 {
			return "", fmt.Errorf("one option, not %d: the ChoicePicker is mutually exclusive", len(l))
		}
		if len(l) == 0 {
			return "", nil
		}
		for _, o := range c.Options {
			if o.Value == l[0] {
				return o.Label, nil
			}
		}
		return "", fmt.Errorf("%q is not one of the ChoicePicker's option values", l[0])
	case "TextField":
		var t string
		if json.Unmarshal(v, &t) != nil {
			return "", fmt.Errorf("a TextField's value is a string")
		}
		if len(t) > maxTextBytes {
			return "", fmt.Errorf("%d bytes, over the %d a TextField's value may be", len(t), maxTextBytes)
		}
		if !utf8.ValidString(t) {
			return "", fmt.Errorf("not UTF-8")
		}
		return t, nil
	case "DateTimeInput":
		var t string
		if json.Unmarshal(v, &t) != nil {
			return "", fmt.Errorf("a DateTimeInput's value is an ISO 8601 string")
		}
		if t != "" && !isISO(t) {
			return "", fmt.Errorf("not an ISO 8601 date, time or date-time")
		}
		return t, nil
	}
	return "", fmt.Errorf("%s binds no value", c.Name)
}

// Pressed is the owner's answer as the portal sent it: A2UI's client-to-server action, its context
// already resolved from the card's data model.
type Pressed struct {
	Button  Component
	Context map[string]json.RawMessage
}

// ReadAction reads raw, an A2UI v0.9.1 client-to-server message, as an action on surface s: the
// surface it names is s, its source is one of s's Buttons and its name that Button's event's, and its
// context holds exactly the Button's keys, each literal as the Button wrote it. The client's
// timestamp is not read: the node keeps its own clock.
func (s Surface) ReadAction(raw []byte) (Pressed, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return Pressed{}, fmt.Errorf("not an A2UI message")
	}
	var a struct {
		Name              string                     `json:"name"`
		SurfaceID         string                     `json:"surfaceId"`
		SourceComponentID string                     `json:"sourceComponentId"`
		Timestamp         string                     `json:"timestamp"`
		Context           map[string]json.RawMessage `json:"context"`
	}
	if err := message(m, "", "action", &a, []string{"name", "surfaceId", "sourceComponentId", "timestamp", "context"}, nil); err != nil {
		return Pressed{}, fmt.Errorf("not an A2UI %s action (%v)", Version, err)
	}
	if a.SurfaceID != s.ID {
		return Pressed{}, fmt.Errorf("that action is on surface %q, not this ask's", a.SurfaceID)
	}
	b, ok := s.Find(a.SourceComponentID)
	if !ok || b.Name != "Button" || b.Action == nil {
		return Pressed{}, fmt.Errorf("no Button by that id answers this ask")
	}
	if a.Name != b.Action.Event.Name {
		return Pressed{}, fmt.Errorf("that Button's event is %q", b.Action.Event.Name)
	}
	if len(a.Context) != len(b.Action.Event.Context) {
		return Pressed{}, fmt.Errorf("the context holds the Button's %d keys, and nothing else", len(b.Action.Event.Context))
	}
	for k, want := range b.Action.Event.Context {
		got, ok := a.Context[k]
		if !ok {
			return Pressed{}, fmt.Errorf("the context has no %q", k)
		}
		if _, isBound := bound(want); isBound {
			continue
		}
		if !sameJSON(want, got) {
			return Pressed{}, fmt.Errorf("%q is the Button's literal, %s", k, want)
		}
	}
	return Pressed{Button: b, Context: a.Context}, nil
}

// sameJSON says a and b are one JSON value, whatever their spacing.
func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ca, _ := json.Marshal(x)
	cb, _ := json.Marshal(y)
	return bytes.Equal(ca, cb)
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
