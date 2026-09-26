package integrationchain

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// `StdioConfigFor` had ZERO production callers — only stdio_test.go set it — so
// every supervised child in the shipped binary was built as
// `StdioConfig{Command: in.Command}` with a nil Env, and stdio.go sets
// `cmd.Env = env` deliberately ("never nil-inherit: empty allow-list means empty
// environment"). A stdio MCP server therefore ran with NO environment at all, and
// there was no way to give it one.
//
// That makes SPEC §12.3's promise — the -full image ships node and uv "so
// supervised stdio integration children (npx / uvx MCP servers) can run
// in-container" — untrue: npx cannot resolve a runtime without PATH, and the
// dominant convention for configuring such a server is environment variables
// (caldav-mcp reads CALDAV_BASE_URL, CALDAV_USERNAME, CALDAV_PASSWORD).
func TestStdioChildGetsItsConfiguredEnvironment(t *testing.T) {
	values := func(context.Context) (map[string]string, error) {
		return map[string]string{
			"integration.cal.env.CALDAV_BASE_URL": "http://radicale:5232/",
			"integration.cal.env.CALDAV_USERNAME": "owner",
			"integration.cal.env.CALDAV_PASSWORD": "pw",
			// not environment: a recipe parameter for the same integration
			"integration.cal.calendar_url": "http://radicale:5232/owner/work/",
			// another integration's environment must not leak into this child
			"integration.other.env.SECRET_TOKEN": "nope",
			"tunnel.frp.token":                   "nope",
		}, nil
	}
	env := stdioEnv(values, "acct-test", "cal", nil)

	for k, want := range map[string]string{
		"CALDAV_BASE_URL": "http://radicale:5232/",
		"CALDAV_USERNAME": "owner",
		"CALDAV_PASSWORD": "pw",
	} {
		if env[k] != want {
			t.Errorf("child env %s = %q, want %q — a stdio server cannot be "+
				"configured at all without this", k, env[k], want)
		}
	}
	for _, k := range []string{"SECRET_TOKEN", "calendar_url", "token"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s leaked into another integration's child environment", k)
		}
	}
	// PATH and HOME are supplied so an `npx`/`uvx` child can resolve its runtime.
	// Without them SPEC §12.3's -full image cannot run one, which is its only
	// reason to exist.
	if env["PATH"] == "" {
		t.Error("no PATH: an npx or uvx child cannot resolve node or python")
	}
	if _, ok := env["HOME"]; !ok {
		t.Error("no HOME: npm and uv both write into it and fail without one")
	}
}

// The allow-list is still an allow-list: an owner-set PATH wins, and nothing
// else from this process's environment is passed through.
func TestStdioEnvIsAnAllowListNotAnInheritance(t *testing.T) {
	t.Setenv("PACT_SHOULD_NOT_LEAK", "leaked")
	values := func(context.Context) (map[string]string, error) {
		return map[string]string{"integration.cal.env.PATH": "/opt/custom/bin"}, nil
	}
	env := stdioEnv(values, "acct-test", "cal", nil)
	if env["PATH"] != "/opt/custom/bin" {
		t.Errorf("an owner-set PATH did not win: %q", env["PATH"])
	}
	if _, ok := env["PACT_SHOULD_NOT_LEAK"]; ok {
		t.Error("the child inherited this process's environment; the allow-list is gone")
	}
	if len(env) > 3 { // PATH + HOME at most, plus nothing else
		t.Errorf("child environment carries more than it was given: %v", keysOf(env))
	}
}

// And the chain must actually install it, or the mechanism has no caller again.
func TestChainWiresStdioConfigForOntoTheManager(t *testing.T) {
	values := func(context.Context) (map[string]string, error) {
		return map[string]string{"integration.cal.env.CALDAV_USERNAME": "owner"}, nil
	}
	c := Build(nil, nil, nil, "", func(string, string, string) {}, nil, values, nil)
	if c.Manager.StdioConfigFor == nil {
		t.Fatal("StdioConfigFor is nil on the shipped manager, so every stdio child " +
			"runs with an empty environment — the exact defect this pins")
	}
	cfg := c.Manager.StdioConfigFor(store.Integration{Slug: "cal", Command: "npx -y caldav-mcp"})
	if cfg.Command != "npx -y caldav-mcp" {
		t.Errorf("command not carried: %q", cfg.Command)
	}
	if cfg.Env["CALDAV_USERNAME"] != "owner" {
		t.Errorf("configured environment did not reach the child config: %v", keysOf(cfg.Env))
	}
}
