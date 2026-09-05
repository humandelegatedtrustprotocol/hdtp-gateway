package fabric

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder captures every command the fabric issues, so these tests assert on what
// Docker was actually ASKED to do. They need no Docker daemon: a fabric driver that
// can only be tested on a machine with containers running is a driver nobody will
// run the unit tests for.
type recorder struct {
	calls []string
	out   map[string]string
	fail  map[string]bool
}

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.calls = append(r.calls, line)
	if r.fail[line] {
		return nil, errors.New("boom")
	}
	if s, ok := r.out[line]; ok {
		return []byte(s), nil
	}
	return []byte("ok"), nil
}

func (r *recorder) saw(sub string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (r *recorder) indexOf(sub string) int {
	for i, c := range r.calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func newFab(r *recorder) *Fabric { return New("pacttest", r.run) }

func TestNetworksAreNamespacedAndInternalWhenAsked(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()

	if _, err := f.Network(ctx, "lan", NetOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Network(ctx, "behind", NetOpts{Internal: true}); err != nil {
		t.Fatal(err)
	}

	// Every object carries the run prefix, so a crashed run can be swept without
	// touching anything else on the developer's machine.
	if !r.saw("network create pacttest-lan") {
		t.Errorf("network not namespaced by the run prefix: %v", r.calls)
	}
	// --internal is what makes T2/T3 honest: a node on an internal network has no
	// route off it at all, so "unreachable" is enforced by Docker rather than by
	// the test politely not dialling.
	if !r.saw("network create --internal pacttest-behind") {
		t.Errorf("internal network was created without --internal: %v", r.calls)
	}
}

func TestNATRouterJoinsBothSegmentsAndMasquerades(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	outside, _ := f.Network(ctx, "wan", NetOpts{})
	inside, _ := f.Network(ctx, "lan", NetOpts{Internal: true})

	if _, err := f.NAT(ctx, "nat1", outside, inside); err != nil {
		t.Fatal(err)
	}

	// It must hold NET_ADMIN — without it iptables inside the router silently fails.
	if !r.saw("--cap-add NET_ADMIN") {
		t.Errorf("NAT router has no NET_ADMIN, so its iptables rules cannot apply: %v", r.calls)
	}
	// It must sit on BOTH segments, or it cannot route between them.
	if !r.saw("network connect pacttest-lan pacttest-nat1") {
		t.Errorf("NAT router was never attached to the inside segment: %v", r.calls)
	}
	if !r.saw("MASQUERADE") {
		t.Errorf("no MASQUERADE rule was installed: %v", r.calls)
	}
	// And it must NOT install any inbound DNAT — the whole point is that the
	// inside is unreachable from outside.
	if r.saw("DNAT") || r.saw("--publish") {
		t.Errorf("NAT router published an inbound path, which defeats the topology: %v", r.calls)
	}
}

func TestShaperNeedsNetAdminAndAppliesNetem(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	c := &Container{Name: "pacttest-node-a"}

	if err := f.Shape(ctx, c, Netem{Latency: "150ms", Loss: "3%"}); err != nil {
		t.Fatal(err)
	}
	if !r.saw("tc qdisc") || !r.saw("netem") {
		t.Errorf("no netem qdisc applied: %v", r.calls)
	}
	// It must run in the target's NETWORK NAMESPACE, not inside it: the node image
	// is distroless and has no shell, so `docker exec node sh -c tc` is exit 127.
	if !r.saw("--network container:pacttest-node-a") {
		t.Errorf("shaping was not applied via the target's netns: %v", r.calls)
	}
	if !r.saw("--cap-add NET_ADMIN") {
		t.Errorf("the shaper has no NET_ADMIN, so tc cannot install a qdisc: %v", r.calls)
	}
	if !r.saw("delay 150ms") || !r.saw("loss 3%") {
		t.Errorf("netem parameters did not reach tc: %v", r.calls)
	}
}

// Partition is the case S7 needs most: not slow, GONE. It must be reversible,
// because half of the scenario is what happens when the network comes back.
func TestPartitionIsAppliedAndLiftedSymmetrically(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	c := &Container{Name: "pacttest-node-a"}

	if err := f.Partition(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !r.saw("loss 100%") {
		t.Errorf("partition did not drop all traffic: %v", r.calls)
	}
	before := len(r.calls)
	if err := f.Heal(ctx, c); err != nil {
		t.Fatal(err)
	}
	healed := strings.Join(r.calls[before:], " | ")
	if !strings.Contains(healed, "qdisc del") {
		t.Errorf("healing did not remove the qdisc: %s", healed)
	}
}

func TestCollectWritesLogsPerContainer(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker logs pacttest-node-a": "hello from a",
	}}
	f := newFab(r)
	ctx := context.Background()
	f.track(&Container{Name: "pacttest-node-a"})

	dir := t.TempDir()
	if err := f.Collect(ctx, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "pacttest-node-a.log"))
	if err != nil {
		t.Fatalf("no log captured for a tracked container: %v", err)
	}
	if !strings.Contains(string(b), "hello from a") {
		t.Errorf("captured log is empty or wrong: %q", b)
	}
}

// A failed scenario must still yield its evidence. If Collect gives up on the
// first unreadable container, the one that crashed — the interesting one — is
// exactly the one whose logs go missing.
func TestCollectKeepsGoingWhenOneContainerFails(t *testing.T) {
	r := &recorder{
		out:  map[string]string{"docker logs pacttest-good": "still here"},
		fail: map[string]bool{"docker logs pacttest-bad": true},
	}
	f := newFab(r)
	ctx := context.Background()
	f.track(&Container{Name: "pacttest-bad"})
	f.track(&Container{Name: "pacttest-good"})

	dir := t.TempDir()
	err := f.Collect(ctx, dir)
	if err == nil {
		t.Error("Collect hid a failure entirely; the caller cannot know evidence is incomplete")
	}
	if _, rerr := os.ReadFile(filepath.Join(dir, "pacttest-good.log")); rerr != nil {
		t.Errorf("a healthy container's logs were skipped because another failed: %v", rerr)
	}
}

// Teardown must remove containers before the networks they sit on, or Docker
// refuses the network removal and the next run collides with the leftovers.
func TestTeardownRemovesContainersBeforeNetworks(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	n, _ := f.Network(ctx, "lan", NetOpts{})
	_, _ = f.Container(ctx, Spec{Name: "node-a", Image: "img", Network: n})

	if err := f.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	ci := r.indexOf("rm -f pacttest-node-a")
	ni := r.indexOf("network rm pacttest-lan")
	if ci < 0 || ni < 0 {
		t.Fatalf("teardown did not remove both: %v", r.calls)
	}
	if ci > ni {
		t.Errorf("network removed before the container on it; Docker will refuse: %v", r.calls)
	}
}

func TestTeardownContinuesAfterAFailedRemoval(t *testing.T) {
	r := &recorder{fail: map[string]bool{"docker rm -f pacttest-node-a": true}}
	f := newFab(r)
	ctx := context.Background()
	n, _ := f.Network(ctx, "lan", NetOpts{})
	_, _ = f.Container(ctx, Spec{Name: "node-a", Image: "img", Network: n})

	if err := f.Teardown(ctx); err == nil {
		t.Error("Teardown reported success despite a failed removal")
	}
	if !r.saw("network rm pacttest-lan") {
		t.Errorf("a failed container removal stopped the network cleanup, leaking it: %v", r.calls)
	}
}

func TestPublishedPortsAndNetworkModeReachDocker(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	if _, err := f.Container(ctx, Spec{
		Name: "node", Image: "img", Ports: []string{"18443:8443"},
	}); err != nil {
		t.Fatal(err)
	}
	if !r.saw("-p 18443:8443") {
		t.Errorf("published port never reached docker: %v", r.calls)
	}
	// A sidecar sharing a node's namespace is how the harness reaches a
	// loopback-bound internal surface WITHOUT the node binding non-loopback,
	// which SPEC §8.3 would refuse without auth and TLS.
	if _, err := f.Container(ctx, Spec{
		Name: "sc", Image: "img", NetworkMode: "container:pacttest-node",
	}); err != nil {
		t.Fatal(err)
	}
	if !r.saw("--network container:pacttest-node") {
		t.Errorf("network mode override never reached docker: %v", r.calls)
	}
	// An alias is how an image whose certificate has a FIXED SAN stays reachable
	// under a prefixed container name. Without it the run prefix and the SAN
	// cannot both hold, and dropping the prefix would make teardown unsafe.
	if _, err := f.Container(ctx, Spec{
		Name: "ca", Image: "img", Aliases: []string{"pebble"},
	}); err != nil {
		t.Fatal(err)
	}
	if !r.saw("--network-alias pebble") {
		t.Errorf("network alias never reached docker: %v", r.calls)
	}
	if _, err := f.Container(ctx, Spec{
		Name: "cli", Image: "img", DNS: []string{"10.0.0.53"},
	}); err != nil {
		t.Fatal(err)
	}
	if !r.saw("--dns 10.0.0.53") {
		t.Errorf("resolver override never reached docker, so a test zone would be "+
			"ignored in favour of the host's: %v", r.calls)
	}
}

// A NAT router on the segment is not enough: an --internal Docker network has no
// gateway, so a container on one has no default route and cannot reach the router
// at all. NAT() promised "outbound but no inbound" and delivered neither half of
// the outbound, which went unnoticed because the live test asserted only that
// inbound was blocked.
func TestDefaultRouteIsAppliedInTheTargetsNamespace(t *testing.T) {
	r := &recorder{}
	f := newFab(r)
	ctx := context.Background()
	c := &Container{Name: "pacttest-node"}

	if err := f.DefaultRoute(ctx, c, "10.9.9.1"); err != nil {
		t.Fatal(err)
	}
	if !r.saw("ip route replace default via 10.9.9.1") {
		t.Errorf("no default route was installed: %v", r.calls)
	}
	// It must run in the TARGET's namespace — the node image is distroless and
	// has neither a shell nor NET_ADMIN of its own.
	if !r.saw("--network container:pacttest-node") || !r.saw("--cap-add NET_ADMIN") {
		t.Errorf("the route was not applied inside the target's netns: %v", r.calls)
	}
}
