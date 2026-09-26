package cli

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// healthcheck probes the internal listener's /healthz; the container HEALTHCHECK
// runs this (distroless has no shell or curl). Exit 0 iff healthy.
func healthcheck(args []string, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("healthcheck", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cfg.InternalBind + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "healthcheck: status", resp.Status)
		return 1
	}
	return 0
}
