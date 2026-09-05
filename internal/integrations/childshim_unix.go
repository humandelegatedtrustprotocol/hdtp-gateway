//go:build unix

package integrations

// Child resource caps (SPEC §6.2): the node re-executes ITSELF as a tiny shim
// that applies setrlimit and then execs the real upstream command in place —
// same pid, same stdio pipes, so mcp.CommandTransport is none the wiser and no
// external prlimit/cgroup tooling is required inside the static image.
//
// RLIMIT_DATA bounds the data segment — the memory a child actually allocates,
// and the enforceable approximation of SPEC §6.2's 512 MiB RSS. RLIMIT_CPU bounds
// cumulative CPU seconds (SIGXCPU); "1 CPU" as a share needs cgroups, which a
// plain binary cannot assume, so the CPU-seconds cap is its approximation too.

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

// ShimSupported reports whether caps can be applied on this platform.
const ShimSupported = true

// RunChildShim is the `__child` entry point: parse --mem/--cpu, apply the
// limits, exec the real command. It only returns on failure.
func RunChildShim(args []string) error {
	var mem, cpu uint64
	var argv []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--mem":
			i++
			if i >= len(args) {
				return fmt.Errorf("child shim: --mem needs a value")
			}
			v, err := strconv.ParseUint(args[i], 10, 64)
			if err != nil {
				return fmt.Errorf("child shim: --mem: %w", err)
			}
			mem = v
		case "--cpu":
			i++
			if i >= len(args) {
				return fmt.Errorf("child shim: --cpu needs a value")
			}
			v, err := strconv.ParseUint(args[i], 10, 64)
			if err != nil {
				return fmt.Errorf("child shim: --cpu: %w", err)
			}
			cpu = v
		case "--":
			argv = args[i+1:]
			i = len(args)
		default:
			return fmt.Errorf("child shim: unknown flag %q", args[i])
		}
	}
	if len(argv) == 0 {
		return fmt.Errorf("child shim: no command after --")
	}
	if mem > 0 {
		if err := applyMemoryCap(mem); err != nil {
			return err
		}
	}
	if cpu > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: cpu, Max: cpu}); err != nil {
			return fmt.Errorf("child shim: RLIMIT_CPU: %w", err)
		}
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("child shim: %w", err)
	}
	// the environment is already exactly the allow-list the supervisor set
	return unix.Exec(path, argv, os.Environ())
}
