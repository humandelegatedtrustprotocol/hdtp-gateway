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

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

// connectStoredIntegrations dials every configured integration, and returns when it has tried
// them all or the node is stopping. It BLOCKS, so `serve` runs it in its background group: a slow
// or dead upstream must not stop the node serving its own surface, and `serve` must not return —
// and close the store — while a dial is still writing to it.
func connectStoredIntegrations(ctx context.Context, ints *integrations.Manager, st store.Store,
	auditFn func(action, resource, outcome string), stderr io.Writer) {

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
				if ctx.Err() != nil {
					// The node is stopping, and the dial ended because it was told to. Recording
					// that as "retrying" put a retry nobody would make into the audit chain.
					return
				}
				auditFn("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "retrying")
				fmt.Fprintf(stderr, "integration %s: %v (will retry)\n", in.Slug, err)
				continue
			}
			auditFn("integration_connect", "account:"+in.AccountID+" integration:"+in.Slug, "ok")
		}
	}
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
