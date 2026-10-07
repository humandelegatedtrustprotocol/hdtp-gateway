package internalui

import (
	"os"
	"strings"
	"testing"
)

// Build rule 1's divergence, named where a test holds it: the owner MCP's send_to_contact starts a
// thread with a topic, and the portal's composer gives none. The node's inbox is one conversation
// per person and shows no topic, so a field would write what its owner never sees here; BatonDeck's
// portal, which lists threads, has the field. A portal send that starts carrying a topic takes this
// entry out.
func TestThePortalComposerGivesNoTopic(t *testing.T) {
	for _, f := range []string{"inbox_pages.go", "messages_pages.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "Topic:") {
			t.Errorf("%s gives a send a topic; if the portal starts threads with one now, remove this divergence", f)
		}
	}
}
