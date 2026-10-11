package testid

import (
	"testing"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// The table answers as the identity core does, case for case, so a door's test that reads it tests
// the core's rule and not a copy that drifted.
func TestTheThreadIDTableIsTheCores(t *testing.T) {
	controls := 0
	for _, c := range ThreadIDs() {
		code, _ := hdtpidentity.ThreadIDRefusal("send_message", map[string]any{"arguments": map[string]any{"thread_id": c.ID}})
		if code != c.Code {
			t.Errorf("%s (%q): the core answers %q, the table %q", c.Name, c.ID, code, c.Code)
		}
		if c.Code == "" {
			controls++
		}
	}
	if controls == 0 {
		t.Fatal("no control of a form: a door that refuses every id would pass")
	}
}
