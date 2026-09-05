package cli

// The environment a supervised stdio child receives (SPEC §6.2, §12.3).

import (
	"context"
	"os"
	"strings"
)

// stdioEnvPrefix is where a child's environment is configured:
// `integration.<slug>.env.<NAME>` — the same settings namespace as this
// install's recipe parameters, and the same one adapter settings use, so there
// is no new storage and no migration. Values whose key looks like a credential
// are sealed at rest by isSecretKey, which covers PASSWORD, TOKEN and KEY.
const stdioEnvPrefix = "env."

// stdioEnv builds the allow-list for one integration's child.
//
// PATH and HOME are supplied unless the owner sets them: an `npx` or `uvx` child
// cannot resolve its runtime without PATH, and both npm and uv write into HOME.
// Nothing else from this process's environment is passed through — the child gets
// what it was given and no more.
func stdioEnv(values func(context.Context) (map[string]string, error), accountID, slug string,
	audit func(action, resource, outcome string)) map[string]string {

	env := map[string]string{}
	if p := os.Getenv("PATH"); p != "" {
		env["PATH"] = p
	}
	if h := os.Getenv("HOME"); h != "" {
		env["HOME"] = h
	}
	if values == nil {
		return env
	}
	all, err := values(context.Background())
	if err != nil {
		if audit != nil {
			audit("stdio_env", "account:"+accountID+" integration:"+slug, "unreadable")
		}
		return env
	}
	prefix := "integration." + slug + "." + stdioEnvPrefix
	for k, v := range all {
		if name := strings.TrimPrefix(k, prefix); name != k && name != "" {
			env[name] = v
		}
	}
	return env
}
