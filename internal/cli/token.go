package cli

import (
	"fmt"
	"io"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

func token(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: hdtp-gateway token <create|list|revoke> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, owner, label, accountID, id string
	fs := commonFlags("token "+sub, &cfgPath, stderr)
	fs.StringVar(&owner, "owner", "", "owner id")
	fs.StringVar(&label, "label", "", "token label")
	fs.StringVar(&accountID, "account", "", "optional account scope")
	fs.StringVar(&id, "id", "", "token id (for revoke)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "token:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "create":
		var out map[string]string
		if err := core.AdminCall(sock, "token.create", map[string]string{"owner": owner, "label": label, "account": accountID}, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		fmt.Fprintln(stdout, "token (shown once):", out["token"])
		fmt.Fprintln(stdout, "id:", out["id"])
		return 0
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "token.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		for _, k := range out {
			fmt.Fprintf(stdout, "%v\t%v\trevoked=%v\n", k["id"], k["label"], k["revoked"])
		}
		return 0
	case "revoke":
		var out string
		if err := core.AdminCall(sock, "token.revoke", map[string]string{"id": id}, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		fmt.Fprintln(stdout, out)
		return 0
	default:
		fmt.Fprintln(stderr, "usage: hdtp-gateway token <create|list|revoke> [flags]")
		return 2
	}
}
