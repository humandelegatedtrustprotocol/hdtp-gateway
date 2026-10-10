package integrations

// Safety rails (SPEC §6.9): annotations and name heuristics sort and badge the
// exposure picker; the four hints are also re-served, normalised, on an exposed
// tool (internal/cli/integrationsurface.go, servedAnnotations). They are
// untrusted; no permission or authorization decision may consult them.
// Default-true hints are pointers: nil means "assume destructive / open-world".

import (
	"encoding/json"
	"strings"
)

// toolAnnotations mirrors the MCP annotation fields the picker reads.
type toolAnnotations struct {
	ReadOnlyHint    bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

// writeWords are the SPEC §6.9 name heuristics for write-capable tools.
var writeWords = []string{
	"create", "delete", "update", "send", "pay", "transfer",
	"remove", "write", "post", "book", "cancel", "modify", "set", "add",
}

// Risk is the picker's advisory assessment of one tool.
type Risk struct {
	Write   bool     `json:"write"`             // true when either signal flags the tool write-capable
	Reasons []string `json:"reasons,omitempty"` // one line per signal that fired
}

// AssessRisk flags a tool write-capable by either signal (SPEC §6.9):
// annotations (readOnlyHint false + destructiveHint nil-or-true assumes
// destructive) or name heuristics. Advisory only.
func AssessRisk(name string, annotations json.RawMessage) Risk {
	var r Risk
	var ann toolAnnotations
	hasAnn := len(annotations) > 0 && json.Unmarshal(annotations, &ann) == nil
	if hasAnn && ann.ReadOnlyHint {
		// explicitly read-only: the annotation signal is quiet; heuristics still run
	} else if !hasAnn || ann.DestructiveHint == nil || *ann.DestructiveHint {
		r.Write = true
		r.Reasons = append(r.Reasons, "not marked read-only; destructive assumed (annotation)")
	}
	lower := strings.ToLower(name)
	for _, w := range writeWords {
		if strings.Contains(lower, w) {
			r.Write = true
			r.Reasons = append(r.Reasons, "name suggests writes: "+w)
			break
		}
	}
	return r
}

// RecipeSuggestion proposes a mapped-mode recipe binding for tools whose names
// look like HDTP core capabilities (SPEC §6.7); rendered pre-selected in the
// picker, freely editable.
func RecipeSuggestion(toolName string) string {
	n := strings.ToLower(toolName)
	switch {
	case strings.Contains(n, "freebusy") || strings.Contains(n, "free_busy") ||
		strings.Contains(n, "availability") || strings.Contains(n, "find_slots") ||
		strings.Contains(n, "suggest_time"):
		return "check_availability"
	case strings.Contains(n, "create_event") || strings.Contains(n, "create-event") ||
		strings.Contains(n, "book"):
		return "book_slot"
	}
	return ""
}
