package ownermcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
)

// The owner MCP names a full contact list `payment_required`, the code the cloud's owner MCP gives
// the same refusal, with the count and the cap in the detail — never `internal`.
func TestAFullContactListIsPaymentRequiredToTheOwnerMCP(t *testing.T) {
	res, err := refused(fmt.Errorf("x: %w", contacts.ErrContactCap))
	if err != nil {
		t.Fatal(err)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, `"code":"payment_required"`) {
		t.Fatalf("the owner MCP answers a full contact list %s", text)
	}
}
