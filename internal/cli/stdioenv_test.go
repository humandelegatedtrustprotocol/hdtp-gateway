package cli

import (
	"context"
	"testing"
)

// The child's environment and the recipe's parameters share a settings prefix,
// and must not share a namespace: a credential reaching an upstream tool ARGUMENT
// would be logged as one.
func TestRecipeParametersExcludeTheChildEnvironment(t *testing.T) {
	b := &capabilityBinder{settings: func(context.Context) (map[string]string, error) {
		return map[string]string{
			"integration.cal.calendar_url":        "http://radicale:5232/owner/work/",
			"integration.cal.env.CALDAV_PASSWORD": "pw",
		}, nil
	}}
	got := b.params(context.Background(), "cal")
	if got["calendar_url"] != "http://radicale:5232/owner/work/" {
		t.Errorf("the recipe parameter did not resolve: %v", got)
	}
	for k := range got {
		if k == "env.CALDAV_PASSWORD" || k == "CALDAV_PASSWORD" {
			t.Errorf("a child credential became a recipe parameter, so it would be "+
				"built into an upstream tool argument: %v", got)
		}
	}
}
