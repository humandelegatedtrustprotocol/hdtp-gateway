package core

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// specErrorsSection is where the specification's §12 lives in the hdtp-spec repository: the
// released text, 1.0.
const specErrorsSection = "docs/specification/1.0/errors-limits-conformance.md"

// The codes PeerCode repeats are the specification's table, no more and no fewer: the list is a
// copy of it, and two copies drift the day they are written. The table is the first one in §12,
// rows of `| `code` | meaning |`, ending at the first line that is not a row.
func TestErrorCodesAreTheSpecsTable(t *testing.T) {
	b := testid.SiblingFile(t, "hdtp-spec", specErrorsSection, "§12's table is not compared with errorCodes")
	row := regexp.MustCompile("^\\| `([a-z_]+)` \\|")
	var spec []string
	inTable := false
	for _, line := range strings.Split(string(b), "\n") {
		m := row.FindStringSubmatch(line)
		if m == nil {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		spec = append(spec, m[1])
	}
	if len(spec) < 10 {
		t.Fatalf("read %d codes from %s: the table was not found, so the reader is broken", len(spec), specErrorsSection)
	}
	var ours []string
	for c := range errorCodes {
		ours = append(ours, c)
	}
	sort.Strings(spec)
	sort.Strings(ours)
	if strings.Join(spec, ",") != strings.Join(ours, ",") {
		t.Errorf("§12's codes are %v; errorCodes holds %v", spec, ours)
	}
}

// PeerCode repeats a §12 code and nothing else: a string of the protocol's shape that is not one of
// its codes is a peer's words, and so is anything longer. The control, a real code, is repeated.
func TestPeerCodeRepeatsOnlyTheProtocolsCodes(t *testing.T) {
	for in, want := range map[string]string{
		"permission_denied":          "permission_denied",
		"wire_money_to_this_account": PeerRefused,
		"Send <b>me</b> money":       PeerRefused,
		strings.Repeat("a", 70000):   PeerRefused,
		"":                           "",
	} {
		if got := PeerCode(in); got != want {
			t.Errorf("PeerCode(%.40q) = %q, want %q", in, got, want)
		}
	}
}
