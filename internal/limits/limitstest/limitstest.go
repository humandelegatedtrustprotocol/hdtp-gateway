// Package limitstest runs the real limits sidecar (cmd/hdtp-limitd) for a test, the way
// internal/testid mints real identities: a test of the node's budgets that ran against a stand-in
// would pass for the stand-in's reasons.
//
// Test-only by use: no non-test file in the module imports it today. internal/integrationtest's
// layering_test.go gives it a rank (1, above internal/limits) but does not forbid a production
// package from importing it.
package limitstest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
)

// BinaryEnv names the sidecar binary a test runs; unset, it is the one `make limitd` builds.
const BinaryEnv = "HDTP_LIMITD"

// root is the module's root, from this file's own path.
func root() string {
	_, here, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(here), "..", "..", "..")
}

// Binary is the sidecar binary a test runs: $HDTP_LIMITD, or what `make limitd` builds. A test
// fails, rather than skips, when neither exists: a budget test that ran against nothing would pass
// for the wrong reason.
func Binary(t testing.TB) string {
	t.Helper()
	p, err := binary()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func binary() (string, error) {
	if p := os.Getenv(BinaryEnv); p != "" {
		return p, nil
	}
	p := filepath.Join(root(), "cmd", "hdtp-limitd", "target", "release", "hdtp-limitd")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("the limits sidecar is not built at %s: run `make limitd` (or set %s)", p, BinaryEnv)
	}
	return p, nil
}

// DefaultConfig is the shipped configuration file, deploy/limitd/limits.json: what a node whose
// operator changed nothing enforces.
func DefaultConfig() string { return filepath.Join(root(), "deploy", "limitd", "limits.json") }

// DefaultRules are the rules of DefaultConfig, read from the file: there is no second copy of the
// numbers to keep equal to it.
func DefaultRules(t testing.TB) limits.Rules {
	t.Helper()
	r, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func defaultRules() (limits.Rules, error) {
	b, err := os.ReadFile(DefaultConfig())
	if err != nil {
		return limits.Rules{}, err
	}
	var doc struct {
		Socket string       `json:"socket"`
		Rules  limits.Rules `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return limits.Rules{}, fmt.Errorf("%s: %w", DefaultConfig(), err)
	}
	return doc.Rules, nil
}

// Sidecar is a real hdtp-limitd a test started, with a client of it.
type Sidecar struct {
	*limits.Client
	// Config is the path of the configuration file the sidecar was started with.
	Config string
	cmd    *exec.Cmd
}

// Start runs the real sidecar on a socket of its own with rules, and stops it when the test ends.
// It returns once the sidecar answers.
func Start(t testing.TB, rules limits.Rules) *Sidecar {
	t.Helper()
	s, stop, err := launch(rules)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return s
}

// LaunchDefault is StartDefault for a TestMain, which has no test to end with: stop ends it.
func LaunchDefault() (s *Sidecar, stop func(), err error) {
	rules, err := defaultRules()
	if err != nil {
		return nil, nil, err
	}
	return launch(rules)
}

func launch(rules limits.Rules) (*Sidecar, func(), error) {
	// A unix socket path is short (104 bytes on macOS); a test's temp dir is not.
	dir, err := os.MkdirTemp("", "limitd")
	if err != nil {
		return nil, nil, err
	}
	socket := filepath.Join(dir, "l.sock")
	config := filepath.Join(dir, "limits.json")
	if err := WriteConfig(config, socket, rules); err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}
	s := &Sidecar{Client: limits.New(socket), Config: config}
	if err := s.run(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}
	return s, func() { s.Stop(); _ = os.RemoveAll(dir) }, nil
}

// StartDefault is Start with the shipped rules.
func StartDefault(t testing.TB) *Sidecar {
	t.Helper()
	return Start(t, DefaultRules(t))
}

// WriteConfig writes a sidecar configuration file.
func WriteConfig(path, socket string, rules limits.Rules) error {
	doc, err := json.Marshal(map[string]any{"socket": socket, "rules": rules})
	if err != nil {
		return err
	}
	return os.WriteFile(path, doc, 0o600)
}

// run starts the sidecar and returns once it answers.
func (s *Sidecar) run() error {
	bin, err := binary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "-config", s.Config) // #nosec G204 -- the sidecar `make limitd` built, or the one HDTP_LIMITD names; test support only
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the limits sidecar: %w", err)
	}
	s.cmd = cmd
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := s.Probe(ctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			s.Stop()
			return fmt.Errorf("the limits sidecar did not answer within 10 s: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Stop kills the sidecar. The client stays: what a node sees when its sidecar is down.
func (s *Sidecar) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
		s.cmd = nil
	}
}

// Restart stops the sidecar and starts it again on the same socket with the same rules: every
// counter is fresh, as after a restart in production (the counters live in its memory).
func (s *Sidecar) Restart(t testing.TB) {
	t.Helper()
	s.Stop()
	if err := s.run(); err != nil {
		t.Fatal(err)
	}
}
