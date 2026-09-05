package cli

// Bringing configured integrations back up (SPEC §6.10).
//
// An integration is a long-lived connection to somebody else's MCP server, and
// the owner configured it once. Without this, a restart left every one of them
// disconnected: the mapped, passthrough and agent-answered tools they back would
// answer `unavailable` forever, and the only way back was for the owner to press
// "connect" in the portal again. That is not a state a node should ever be in
// unattended.
//
// Connect already arms a per-integration health cycle and retries a failed
// initial connect, so a dependency that is down at boot is not a startup
// problem — it recovers on its own when it returns.

import (
	"context"
	"fmt"
	"io"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

// connectStoredIntegrations dials every configured integration in the
// background. It never blocks startup: a slow or dead upstream must not stop the
// node serving its own surface.
func connectStoredIntegrations(ctx context.Context, ints *integrations.Manager, st store.Store,
	auditFn func(action, resource, outcome string), stderr io.Writer) {

	go func() {
		accounts, err := st.ListAccounts(ctx)
		if err != nil {
			return
		}
		for _, a := range accounts {
			rows, err := st.ListIntegrations(ctx, a.ID)
			if err != nil {
				continue
			}
			for _, in := range rows {
				if ctx.Err() != nil {
					return
				}
				// A failure here is expected and self-healing: Connect arms the
				// health cycle either way, so the integration recovers when its
				// upstream does.
				if err := ints.Connect(ctx, in.ID); err != nil {
					auditFn("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "retrying")
					fmt.Fprintf(stderr, "integration %s: %v (will retry)\n", in.Slug, err)
					continue
				}
				auditFn("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
			}
		}
	}()
}

// disconnectIntegrations stops the health cycles on shutdown so supervised
// stdio children do not outlive the node.
func disconnectIntegrations(ints *integrations.Manager, st store.Store) {
	ctx := context.Background()
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return
	}
	for _, a := range accounts {
		rows, err := st.ListIntegrations(ctx, a.ID)
		if err != nil {
			continue
		}
		for _, in := range rows {
			_ = ints.Disconnect(ctx, in.ID)
		}
	}
}
