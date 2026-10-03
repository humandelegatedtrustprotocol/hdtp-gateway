package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

func migrate(args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("migrate", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	// SPEC §12.1: offline command — refuse while the node holds the lock.
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	defer lock.Release()

	s, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	fmt.Fprintln(stdout, "migrations applied")
	return 0
}
