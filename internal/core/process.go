package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// ProcessName names this node process among every process that will ever share its store (SPEC
// §11.1): the host, the pid, and random bytes. It is what the leases on background work and on an
// integration's token refresh are held under.
var ProcessName = func() string {
	host, _ := os.Hostname()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), hex.EncodeToString(b))
}()
