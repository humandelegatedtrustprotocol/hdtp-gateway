// Package fabric stands scenario topologies up and takes them down again.
//
// It drives the `docker` CLI through an injected Runner rather than the Docker SDK.
// That is a deliberate match for the product's own preference — few dependencies,
// shell out to the tool that is already installed — and it makes the driver
// testable with no daemon running, which matters because a fabric nobody can unit
// test is a fabric whose bugs surface only inside failing scenarios.
//
// Two properties carry the topologies of docs/harness-design.md §3:
//
//   - An INTERNAL Docker network has no route off it. That is what makes "node B is
//     unreachable" true by construction in T2, rather than true because the test
//     politely declined to dial.
//   - A NAT router container joins both segments and MASQUERADEs outbound. It
//     installs no inbound DNAT, so the asymmetry a real NAT imposes is real here.
package fabric

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/tech-sumit/pact-gateway/harness/images"
)

// Runner executes one command. Injected so the driver is testable without Docker.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Local is the Runner every live test uses: the command on this machine, with what it printed to
// stdout and stderr together, because a failed docker command explains itself on stderr.
func Local(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Network is one Docker network created by this run.
type Network struct {
	Name     string // fully qualified, prefix included
	Internal bool
}

// NetOpts configures a network.
type NetOpts struct {
	// Internal removes the network's route to the outside world. A container with
	// only internal networks cannot be reached from, or reach, anything else.
	Internal bool
	// Routable addresses the network from 198.18.0.0/15 (RFC 2544's benchmarking block) instead of
	// Docker's private pools. The node's SSRF guard (SPEC §7.5) refuses loopback, unspecified, RFC 1918,
	// unique-local, link-local and CGNAT addresses and nothing else, so a container here stands
	// where a host on the internet stands. On a default network every address is RFC 1918, and a
	// fetch the guard must judge hop by hop is refused at the first one, for the wrong reason.
	Routable bool
}

// Container is one container created by this run.
type Container struct {
	Name string // fully qualified, prefix included
}

// Spec describes a container to start.
type Spec struct {
	Name    string
	Image   string
	Network *Network
	Env     map[string]string
	Cmd     []string
	// CapAdd grants Linux capabilities. NET_ADMIN is required for anything that
	// runs iptables or tc; nothing else in the fabric needs a capability.
	CapAdd []string
	// Ports publishes container ports to the host, in docker's own "host:container"
	// form. Used only where the test process itself must dial in — the peer driver
	// and the owner MCP — never to make a node reachable to another container,
	// which the fabric's networks already handle.
	Ports []string
	// Volumes are docker -v arguments, "host:container[:ro]". Used for config a
	// service reads from disk — several upstream images ignore CLI flags in favour
	// of a config file, which is a silent no-op rather than an error.
	Volumes []string
	// DNS replaces the upstream resolvers the container's embedded Docker DNS
	// forwards to. Container names still resolve; everything else goes here,
	// which is what makes an authoritative test zone genuinely authoritative.
	DNS []string
	// Aliases are extra names the container answers to on its network. Needed
	// when an off-the-shelf image ships a certificate whose SAN is a fixed name:
	// the run prefix keeps container names sweepable, and an alias lets the name
	// in the certificate resolve anyway.
	Aliases []string
	// NetworkMode overrides --network entirely, e.g. "container:<name>" to share
	// another container's namespace. That is how a sidecar reaches a node's
	// loopback-bound internal surface without the node binding non-loopback.
	NetworkMode string
}

// Netem describes link impairment applied inside a container.
type Netem struct {
	Latency string // e.g. "150ms"
	Jitter  string // e.g. "20ms"; ignored unless Latency is set
	Loss    string // e.g. "3%"
}

// Fabric owns everything one scenario created, and can remove all of it.
type Fabric struct {
	prefix string
	run    Runner

	// Creation order is retained so teardown can reverse it: containers must go
	// before the networks they sit on, or Docker refuses the network removal.
	containers []*Container
	networks   []*Network

	// pick draws where a routable network's search for a free /24 starts; nil is crypto/rand.
	pick func() int
}

func New(prefix string, run Runner) *Fabric {
	return &Fabric{prefix: prefix, run: run}
}

// Prefix is the run's namespace. Every object this fabric creates carries it, so a
// crashed run can be swept without touching anything else on the machine.
func (f *Fabric) Prefix() string { return f.prefix }

// Exec runs a command inside a container. The node image is distroless — no shell —
// so callers invoke the binary directly rather than wrapping it in `sh -c`.
func (f *Fabric) Exec(ctx context.Context, c *Container, args ...string) ([]byte, error) {
	full := append([]string{"exec", c.Name}, args...)
	return f.run(ctx, "docker", full...)
}

// Raw runs an arbitrary command through this fabric's runner. Used by checks that
// need docker verbs the fabric does not model — stopping a node, or mounting its
// volumes into a throwaway sidecar.
func (f *Fabric) Raw(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.run(ctx, name, args...)
}

// qualify namespaces every object by the run prefix, so a crashed run can be swept
// without touching anything else on the machine.
func (f *Fabric) qualify(name string) string { return f.prefix + "-" + name }

// Name is the full name this fabric gives an object called name: what a container is reached
// by on its network, before or after it exists (a network alias, a public URL).
func (f *Fabric) Name(name string) string { return f.qualify(name) }

// runToken is drawn once per test binary. With it, two runs of one scenario at the same time —
// two worktrees, two terminals — get different container and network names instead of
// colliding on them.
var runToken = func() string {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}()

// PrefixFor is the fabric prefix for a registered scenario: "pact", its id in lower case, and
// this run's token, e.g. "pacts13-7f3a". It is a valid DNS label, because container names are
// the addresses nodes dial and leaves name.
func PrefixFor(id string) string { return "pact" + strings.ToLower(id) + "-" + runToken }

// The ports FreePort has handed out in this process.
var (
	portsMu sync.Mutex
	given   = map[int]bool{}
)

// FreePort is a host TCP port for a container to publish: the kernel picks one nobody is
// listening on, and this process never hands the same one out twice. Hand-picked ports collided
// (18680 and 18681 were claimed by two scenarios, 18691 and 18692 by two more). Another process
// can still take the port between this call and `docker run`; that fails loudly as "port is
// already allocated", never as a wrong result.
func FreePort() (string, error) {
	portsMu.Lock()
	defer portsMu.Unlock()
	for range 20 {
		l, err := net.Listen("tcp", ":0")
		if err != nil {
			return "", fmt.Errorf("fabric: finding a free port: %w", err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if !given[p] {
			given[p] = true
			return strconv.Itoa(p), nil
		}
	}
	return "", errors.New("fabric: the kernel kept offering ports this process already handed out")
}

func (f *Fabric) track(c *Container) { f.containers = append(f.containers, c) }

// Network creates a Docker network for this run.
func (f *Fabric) Network(ctx context.Context, name string, o NetOpts) (*Network, error) {
	full := f.qualify(name)
	args := []string{"network", "create"}
	if o.Internal {
		args = append(args, "--internal")
	}
	if !o.Routable {
		if _, err := f.run(ctx, "docker", append(args, full)...); err != nil {
			return nil, fmt.Errorf("fabric: creating network %s: %w", full, err)
		}
	} else if err := f.routable(ctx, args, full); err != nil {
		return nil, err
	}
	n := &Network{Name: full, Internal: o.Internal}
	f.networks = append(f.networks, n)
	return n, nil
}

// routableSubnets is how many /24s 198.18.0.0/15 holds.
const routableSubnets = 512

// routable creates a network on a /24 of 198.18.0.0/15. The block is shared by every run on the
// machine, so the /24 is drawn at random (f.pick) and, where Docker answers that the pool
// overlaps one already in use, the next is tried; any other refusal is the answer.
func (f *Fabric) routable(ctx context.Context, args []string, full string) error {
	pick := f.pick
	if pick == nil {
		pick = func() int {
			var b [2]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			return int(b[0])<<8 | int(b[1])
		}
	}
	start := pick()
	var last []byte
	for i := range 32 {
		n := (start + i) % routableSubnets
		subnet := fmt.Sprintf("198.%d.%d.0/24", 18+n/256, n%256)
		out, err := f.run(ctx, "docker", append(args, "--subnet", subnet, full)...)
		if err == nil {
			return nil
		}
		if !strings.Contains(string(out), "overlaps") {
			return fmt.Errorf("fabric: creating network %s on %s: %w: %s", full, subnet, err, strings.TrimSpace(string(out)))
		}
		last = out
	}
	return fmt.Errorf("fabric: creating network %s: 32 subnets of 198.18.0.0/15 were taken: %s", full, strings.TrimSpace(string(last)))
}

// Connect attaches a running container to a further network.
func (f *Fabric) Connect(ctx context.Context, c *Container, n *Network) error {
	if _, err := f.run(ctx, "docker", "network", "connect", n.Name, c.Name); err != nil {
		return fmt.Errorf("fabric: attaching %s to %s: %w", c.Name, n.Name, err)
	}
	return nil
}

// Container starts a container on a network.
func (f *Fabric) Container(ctx context.Context, s Spec) (*Container, error) {
	full := f.qualify(s.Name)
	args := []string{"run", "-d", "--name", full}
	switch {
	case s.NetworkMode != "":
		args = append(args, "--network", s.NetworkMode)
	case s.Network != nil:
		args = append(args, "--network", s.Network.Name)
	}
	for _, p := range s.Ports {
		args = append(args, "-p", p)
	}
	for _, v := range s.Volumes {
		args = append(args, "-v", v)
	}
	for _, a := range s.Aliases {
		args = append(args, "--network-alias", a)
	}
	for _, d := range s.DNS {
		args = append(args, "--dns", d)
	}
	for _, c := range s.CapAdd {
		args = append(args, "--cap-add", c)
	}
	for k, v := range s.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, s.Image)
	args = append(args, s.Cmd...)
	if _, err := f.run(ctx, "docker", args...); err != nil {
		return nil, fmt.Errorf("fabric: starting %s: %w", full, err)
	}
	c := &Container{Name: full}
	f.track(c)
	return c, nil
}

// NAT starts a router between an outside and an inside segment: MASQUERADE
// outbound, nothing inbound.
//
// The router sleeps rather than running a service, because all the work is done by
// the iptables rules installed into its network namespace. Docker's own routing
// does the forwarding once the container is attached to both networks.
func (f *Fabric) NAT(ctx context.Context, name string, outside, inside *Network) (*Container, error) {
	c, err := f.Container(ctx, Spec{
		Name: name, Image: images.Alpine, Network: outside,
		CapAdd: []string{"NET_ADMIN"},
		Cmd:    []string{"sh", "-c", "sleep infinity"},
	})
	if err != nil {
		return nil, err
	}
	if err := f.Connect(ctx, c, inside); err != nil {
		return nil, err
	}
	// Deliberately outbound-only. No DNAT, no --publish: the inside segment stays
	// undialable, which is the property T2 exists to exercise.
	script := "apk add --no-cache iptables >/dev/null 2>&1; " +
		"sysctl -w net.ipv4.ip_forward=1 >/dev/null; " +
		"iptables -t nat -A POSTROUTING -j MASQUERADE"
	if _, err := f.run(ctx, "docker", "exec", c.Name, "sh", "-c", script); err != nil {
		return nil, fmt.Errorf("fabric: installing MASQUERADE on %s: %w", c.Name, err)
	}
	return c, nil
}

// IPOn reports a container's address on one specific network. A container
// attached to several networks has several addresses, and which one a peer must
// use depends on where that peer sits.
func (f *Fabric) IPOn(ctx context.Context, c *Container, net *Network) (string, error) {
	out, err := f.run(ctx, "docker", "inspect", "-f",
		"{{(index .NetworkSettings.Networks \""+net.Name+"\").IPAddress}}", c.Name)
	if err != nil {
		return "", fmt.Errorf("fabric: inspecting %s on %s: %w", c.Name, net.Name, err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" || ip == "<no value>" {
		return "", fmt.Errorf("fabric: %s has no address on %s", c.Name, net.Name)
	}
	return ip, nil
}

// DefaultRoute points a container's default route at a gateway.
//
// It is REQUIRED for a NAT router to be usable, and that is not obvious: an
// `--internal` Docker network has no gateway, so a container on one has no
// default route at all and cannot reach the router even though the router is
// right there on the segment. NAT() therefore gave outbound to nobody until this
// existed — and nothing noticed, because the live NAT test asserted only the
// "no inbound" half of its own promise.
//
// Applied from a sidecar in the target's namespace: the node image is distroless
// and has neither a shell nor NET_ADMIN.
func (f *Fabric) DefaultRoute(ctx context.Context, target *Container, gateway string) error {
	out, err := f.netnsExec(ctx, target, "ip route replace default via "+gateway)
	if err != nil {
		return fmt.Errorf("fabric: setting default route on %s via %s: %w (%s)",
			target.Name, gateway, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// netnsExec runs a command inside another container's NETWORK namespace.
//
// This is what makes shaping work against a distroless node: `tc` operates on the
// namespace, not on the filesystem, so a throwaway Alpine container sharing the
// node's netns can install a qdisc that applies to the node's traffic. Running it
// "inside" the node was exit status 127 — there is no `sh` in there to run.
//
// The image carries iproute2 (tc) ALREADY INSTALLED (images.ShaperDockerfile). That is not a
// convenience: a shaper that installs its tools at run time cannot heal a partition it created —
// `apk add` needs the very network that is being dropped. Observed as `sh: tc: not found` while
// lifting a 100% loss qdisc.
func (f *Fabric) netnsExec(ctx context.Context, target *Container, script string) ([]byte, error) {
	if err := EnsureShaper(ctx, f.run); err != nil {
		return nil, err
	}
	return f.run(ctx, "docker", "run", "--rm",
		"--network", "container:"+target.Name,
		"--cap-add", "NET_ADMIN",
		images.Shaper, "sh", "-c", script)
}

// EnsureShaper builds the shaper image if this machine does not have it yet. The Dockerfile is
// written to a temporary context on disk because `docker build -` reads it from stdin, which a
// Runner does not supply (measured 2026-09-27: "failed to read dockerfile: no local sources
// enabled"). `make harness-shaper` calls this too, so there is one recipe.
func EnsureShaper(ctx context.Context, run Runner) error {
	if _, err := run(ctx, "docker", "image", "inspect", images.Shaper); err == nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "pact-shaper")
	if err != nil {
		return fmt.Errorf("fabric: building the shaper image: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(images.ShaperDockerfile), 0o644); err != nil {
		return err
	}
	if out, err := run(ctx, "docker", "build", "-t", images.Shaper, dir); err != nil {
		return fmt.Errorf("fabric: building the shaper image: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Shape applies link impairment to a container's network namespace. Replaces any
// existing qdisc, so repeated calls state the current condition rather than
// stacking impairments invisibly.
func (f *Fabric) Shape(ctx context.Context, c *Container, n Netem) error {
	var netem []string
	if n.Latency != "" {
		netem = append(netem, "delay", n.Latency)
		if n.Jitter != "" {
			netem = append(netem, n.Jitter)
		}
	}
	if n.Loss != "" {
		netem = append(netem, "loss", n.Loss)
	}
	if len(netem) == 0 {
		return errors.New("fabric: Shape called with no impairment; use Heal to clear one")
	}
	out, err := f.netnsExec(ctx, c, "tc qdisc replace dev eth0 root netem "+strings.Join(netem, " "))
	if err != nil {
		return fmt.Errorf("fabric: shaping %s: %w (%s)", c.Name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Partition takes the link away entirely — the case a retry path must survive.
func (f *Fabric) Partition(ctx context.Context, c *Container) error {
	return f.Shape(ctx, c, Netem{Loss: "100%"})
}

// Heal removes all impairment. Half of every resilience scenario is what happens
// when the network comes back, so this is not optional cleanup.
func (f *Fabric) Heal(ctx context.Context, c *Container) error {
	out, err := f.netnsExec(ctx, c, "tc qdisc del dev eth0 root 2>/dev/null || true")
	if err != nil {
		return fmt.Errorf("fabric: healing %s: %w (%s)", c.Name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Collect writes each tracked container's logs into dir.
//
// It gathers everything it can and reports the failures together. Stopping at the
// first unreadable container would lose the evidence for every container after it —
// and the one that failed is usually the one that crashed, which is exactly the
// log somebody needs.
func (f *Fabric) Collect(ctx context.Context, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var failures []error
	for _, c := range f.containers {
		out, err := f.run(ctx, "docker", "logs", c.Name)
		if err != nil {
			failures = append(failures, fmt.Errorf("logs %s: %w", c.Name, err))
			continue
		}
		p := filepath.Join(dir, c.Name+".log")
		if werr := os.WriteFile(p, out, 0o644); werr != nil {
			failures = append(failures, fmt.Errorf("writing %s: %w", p, werr))
		}
	}
	return errors.Join(failures...)
}

// Teardown removes everything this run created, containers first.
//
// It continues past failures for the same reason Collect does: a leaked network is
// worse than a reported error, because it collides with the next run.
func (f *Fabric) Teardown(ctx context.Context) error {
	var failures []error
	for i := len(f.containers) - 1; i >= 0; i-- {
		if _, err := f.run(ctx, "docker", "rm", "-f", f.containers[i].Name); err != nil {
			failures = append(failures, fmt.Errorf("removing %s: %w", f.containers[i].Name, err))
		}
	}
	for i := len(f.networks) - 1; i >= 0; i-- {
		if _, err := f.run(ctx, "docker", "network", "rm", f.networks[i].Name); err != nil {
			failures = append(failures, fmt.Errorf("removing network %s: %w", f.networks[i].Name, err))
		}
	}
	f.containers, f.networks = nil, nil
	return errors.Join(failures...)
}
