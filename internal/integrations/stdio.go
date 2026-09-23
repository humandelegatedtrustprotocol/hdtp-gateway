package integrations

// Supervised stdio children (SPEC §6.2): a stdio-supervised integration runs a
// local child process over mcp.CommandTransport. The supervisor enforces exactly
// what the spec demands — argv with no shell interpolation, an environment
// allow-list (the child sees ONLY configured variables, never the node's
// environ), exponential restart backoff 1 s → 60 s, and give-up after N
// consecutive failures inside a window, after which dialing fails `unavailable`
// until the owner reconnects. Runtime note (SPEC §12): the slim image ships no
// node/uv — stdio servers needing them require the `-full` tag or a mount.

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	backoffFloor   = 1 * time.Second
	backoffCeiling = 60 * time.Second
	// DefaultMaxRestarts / DefaultFailureWindow: give-up after 5 consecutive
	// failures within 5 minutes (SPEC §6.2).
	DefaultMaxRestarts   = 5
	DefaultFailureWindow = 5 * time.Minute
)

// ErrUnavailable marks a child past its give-up threshold: tools fail
// `unavailable` (SPEC §6.10) until the owner explicitly reconnects.
var ErrUnavailable = fmt.Errorf("integrations: child unavailable: gave up restarting; reconnect to retry")

const (
	// DefaultMaxMemoryBytes is SPEC §6.2's per-child cap: 512 MiB.
	DefaultMaxMemoryBytes int64 = 512 << 20
)

// StdioConfig is the owner-configured child description.
type StdioConfig struct {
	Command           string            // argv line; conservatively tokenized, never a shell
	Env               map[string]string // allow-list: exactly what the child receives
	TerminateDuration time.Duration
	MaxRestarts       int
	FailureWindow     time.Duration
	// MaxMemoryBytes caps the memory the child may allocate (RLIMIT_DATA, the
	// enforceable approximation of SPEC §6.2's RSS); 0 = the 512 MiB default;
	// negative = uncapped (explicit owner choice).
	MaxMemoryBytes int64
	// MaxCPUSeconds caps cumulative CPU time (RLIMIT_CPU) — the documented
	// approximation of SPEC §6.2's "1 CPU"; 0 = uncapped.
	MaxCPUSeconds int64
	// Shim is the command prefix that applies the caps before exec'ing the
	// real child; nil = this binary's `__child` mode. Tests inject their own.
	Shim []string
	// NoShim runs the child uncapped (platforms without setrlimit, or tests
	// of the bare command path).
	NoShim bool
}

// Warn receives one-line operator warnings (uncapped children); nil = discard.
var Warn = func(string) {}

func defaultShim() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return []string{exe, "__child"}
}

// Supervisor paces one child's restarts. It is NOT the process manager — the
// SDK transport owns the process; the supervisor owns whether and when a new
// one may be started.
type Supervisor struct {
	Config StdioConfig
	Sleep  func(time.Duration) // seam; nil = time.Sleep
	Now    func() time.Time    // seam; nil = time.Now

	mu           sync.Mutex
	failures     int
	firstFailure time.Time
}

func (s *Supervisor) sleep(d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (s *Supervisor) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SetConfig replaces the child config under the supervisor's own lock (the
// Manager refreshes it from the row on every dial).
func (s *Supervisor) SetConfig(c StdioConfig) {
	s.mu.Lock()
	s.Config = c
	s.mu.Unlock()
}

func (s *Supervisor) config() StdioConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Config
}

// maxRestartsOf / windowOf resolve defaults from a config SNAPSHOT — never
// touching s.mu, so they are safe inside locked sections.
func maxRestartsOf(c StdioConfig) int {
	if c.MaxRestarts > 0 {
		return c.MaxRestarts
	}
	return DefaultMaxRestarts
}

func windowOf(c StdioConfig) time.Duration {
	if c.FailureWindow > 0 {
		return c.FailureWindow
	}
	return DefaultFailureWindow
}

// Gate is called before every launch attempt: it enforces give-up and, on a
// retry, sleeps the exponential backoff. Failures older than the window are
// forgiven (they were not "consecutive within the window").
func (s *Supervisor) Gate() error {
	s.mu.Lock()
	cfg := s.Config
	if s.failures > 0 && s.now().Sub(s.firstFailure) > windowOf(cfg) {
		s.failures = 0
	}
	failures := s.failures
	s.mu.Unlock()
	if failures >= maxRestartsOf(cfg) {
		return ErrUnavailable
	}
	if failures > 0 {
		s.sleep(Backoff(failures))
	}
	return nil
}

// Backoff is the restart delay after n consecutive failures: 1s, 2s, 4s … 60s.
func Backoff(n int) time.Duration {
	d := backoffFloor
	for i := 1; i < n; i++ {
		d *= 2
		if d >= backoffCeiling {
			return backoffCeiling
		}
	}
	if d > backoffCeiling {
		return backoffCeiling
	}
	return d
}

// NoteFailure records a failed launch or a child death.
func (s *Supervisor) NoteFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == 0 {
		s.firstFailure = s.now()
	}
	s.failures++
}

// NoteSuccess resets pacing after a healthy connect.
func (s *Supervisor) NoteSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
}

// Reset clears give-up state: the owner's Reconnect (Manager.Reconnect), and nothing else.
func (s *Supervisor) Reset() { s.NoteSuccess() }

// BuildCmd constructs the child command: tokenized argv, no shell, environment
// exactly the allow-list — the node's environ NEVER leaks in (SPEC §6.2).
func (s *Supervisor) BuildCmd() (*exec.Cmd, error) {
	cfg := s.config()
	argv, err := SplitCommand(cfg.Command)
	if err != nil {
		return nil, err
	}
	mem := cfg.MaxMemoryBytes
	if mem == 0 {
		mem = DefaultMaxMemoryBytes
	}
	capped := !cfg.NoShim && ShimSupported && (mem > 0 || cfg.MaxCPUSeconds > 0)
	shim := cfg.Shim
	if capped && shim == nil {
		shim = defaultShim()
		if shim == nil {
			capped = false
		}
	}
	if !capped {
		if !cfg.NoShim {
			Warn(fmt.Sprintf("integrations: child %q runs WITHOUT resource caps on this platform (SPEC §6.2)", argv[0]))
		}
	} else {
		full := append([]string{}, shim...)
		if mem > 0 {
			full = append(full, "--mem", strconv.FormatInt(mem, 10))
		}
		if cfg.MaxCPUSeconds > 0 {
			full = append(full, "--cpu", strconv.FormatInt(cfg.MaxCPUSeconds, 10))
		}
		full = append(full, "--")
		argv = append(full, argv...)
	}
	// #nosec G204 -- argv is the OWNER's integration config; running what the owner
	// configured is the feature. No peer input reaches it.
	cmd := exec.Command(argv[0], argv[1:]...)
	env := make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env // never nil-inherit: empty allow-list means empty environment
	return cmd, nil
}

// SplitCommand tokenizes a command line into argv with single/double quotes and
// nothing else: shell metacharacters are refused outright rather than passed
// through, so a configured command can never smuggle interpolation.
func SplitCommand(line string) ([]string, error) {
	var argv []string
	var cur strings.Builder
	inField := false
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				cur.WriteByte(ch)
			}
		case ch == '\'' || ch == '"':
			quote = ch
			inField = true
		case ch == ' ' || ch == '\t':
			if inField {
				argv = append(argv, cur.String())
				cur.Reset()
				inField = false
			}
		case strings.ContainsRune("|&;<>$`()*?[]{}~#\\\n", rune(ch)):
			return nil, fmt.Errorf("integrations: shell metacharacter %q refused in command", ch)
		default:
			cur.WriteByte(ch)
			inField = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("integrations: unterminated quote in command")
	}
	if inField {
		argv = append(argv, cur.String())
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("integrations: empty command")
	}
	return argv, nil
}
