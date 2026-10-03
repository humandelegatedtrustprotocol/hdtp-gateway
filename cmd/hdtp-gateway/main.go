// Command hdtp-gateway is a self-hosted personal node for the HDTP protocol.
// See SPEC.md for the product specification and PLAN.md for the build plan.
package main

import (
	"os"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/cli"
)

// version is stamped by the release build via -ldflags; the default marks dev builds.
var version = "0.0.0-dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], version, os.Stdout, os.Stderr))
}
