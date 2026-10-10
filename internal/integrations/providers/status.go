package providers

import (
	"context"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

// Status implements get_status (HDTP §6.2): node-local status by default; a
// recipe MAY source it from an upstream tool instead (SPEC §6.7).
type Status struct {
	// Local answers when no recipe sources the status; nil = "available".
	Local func(ctx context.Context) (string, error)
	// Call reaches the upstream tool a get_status binding names.
	Call   Caller
	Recipe *integrations.Recipe // nil or recipe without get_status = local
}

// GetStatus returns the recipe-sourced status when Recipe binds get_status: it
// calls the bound tool and returns the string at Out["status"], or an error if
// the call fails or that path is absent or not a string. Otherwise it returns
// Local's answer, or "available" when Local is nil.
func (s *Status) GetStatus(ctx context.Context) (string, error) {
	if s.Recipe != nil {
		if b, ok := s.Recipe.Capabilities[core.ToolGetStatus]; ok {
			args, err := integrations.BuildArgs(b, map[string]any{})
			if err != nil {
				return "", err
			}
			res, err := s.Call(ctx, b.Tool, args)
			if err != nil {
				return "", err
			}
			path := b.Out["status"]
			v, ok := integrations.LookupString(res, path)
			if !ok {
				return "", fmt.Errorf("providers: response misses %q", path)
			}
			return v, nil
		}
	}
	if s.Local == nil {
		return "available", nil
	}
	return s.Local(ctx)
}
