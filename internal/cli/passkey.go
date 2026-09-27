package cli

import (
	"fmt"
	"io"

	"github.com/pact-cloud/pact-gateway/internal/core"
)

func passkey(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway passkey <list|remove|reset-wizard> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, id string
	fs := commonFlags("passkey "+sub, &cfgPath, stderr)
	fs.StringVar(&id, "id", "", "passkey id (for remove)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "passkey:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "passkey.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		for _, k := range out {
			fmt.Fprintf(stdout, "%v\t%v\towner=%v\n", k["id"], k["tag"], k["owner_id"])
		}
		return 0
	case "remove":
		var out string
		if err := core.AdminCall(sock, "passkey.remove", map[string]string{"id": id}, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		fmt.Fprintln(stdout, out)
		return 0
	case "reset-wizard":
		var out map[string]string
		if err := core.AdminCall(sock, "passkey.reset-wizard", nil, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		fmt.Fprintln(stdout, "one-time setup URL (24h, single use):")
		fmt.Fprintln(stdout, out["url"])
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway passkey <list|remove|reset-wizard> [flags]")
		return 2
	}
}
