package providers

import (
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

// Status implements get_status (PACT §6.2): node-local status by default; a
// recipe MAY source it from an upstream tool instead (SPEC §6.7).
type Status struct {
	Local  func(ctx context.Context) (string, error)
	Call   Caller
	Recipe *integrations.Recipe // nil or recipe without get_status = local
}

func (s *Status) GetStatus(ctx context.Context) (string, error) {
	if s.Recipe != nil {
		if b, ok := s.Recipe.Capabilities["get_status"]; ok {
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
