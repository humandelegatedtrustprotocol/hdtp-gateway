// Package registry makes a live scenario DATA: an id, a name, the tier that runs it, what it needs
// from the machine, and how long it may take. The spec is a literal in the scenario's own test
// function, passed to Start:
//
//	func TestSomething(t *testing.T) {
//		ctx := registry.Start(t, registry.Spec{
//			ID: "S2", Name: "pairing and a first message, end to end", Tier: registry.PR,
//			Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
//			Timeout: 8 * time.Minute,
//		})
//		...
//	}
//
// Start checks the needs, bounds the scenario by its Timeout, and records its verdict (PASS, FAIL,
// or SKIPPED with the reason) as JSON. Scan reads the same literals out of the source, so
// `harness list`, the Makefile's tiers and the table in docs/harness-design.md all come from the
// one place a scenario is written, and none of them can name a scenario that does not exist.
//
// It exists because a scenario used to be a plain Test function whose number lived in a comment,
// tiers chose scenarios by a regular expression over test names, and a skip read as a pass:
// nightly skipped two scenarios on every run and said nothing.
package registry

import (
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Tier is how often a scenario runs. Tiers nest: everything in Fabric runs in PR, everything in PR
// runs in Nightly.
type Tier string

const (
	// Fabric is the fabric proving itself: networks, NAT, the peer driver and the audit-chain
	// invariant against real containers. `make harness-live`.
	Fabric Tier = "fabric"
	// PR adds the scenarios with the most signal per second. `make harness-pr`.
	PR Tier = "pr"
	// Nightly is every scenario. `make harness-nightly`.
	Nightly Tier = "nightly"
)

// Tiers is every tier, smallest first.
var Tiers = []Tier{Fabric, PR, Nightly}

// Includes reports whether running tier t runs a scenario whose own tier is s.
func (t Tier) Includes(s Tier) bool {
	return slices.Index(Tiers, s) >= 0 && slices.Index(Tiers, s) <= slices.Index(Tiers, t)
}

// Need is something a scenario requires of the machine it runs on.
type Need string

const (
	// Docker is a Docker daemon that answers.
	Docker Need = "docker"
	// NodeImage is images.Node, built by `make harness-image`.
	NodeImage Need = "node-image"
	// CaldavImage is images.Caldav, built by `make harness-image-caldav`.
	CaldavImage Need = "caldav-image"
	// Chrome is a Chrome the portal driver can launch headless.
	Chrome Need = "chrome"
	// Kernel is an aarch64 guest kernel named by HDTP_HARNESS_KERNEL (`make harness-kernel`)
	// and a hardware-accelerated qemu-system-aarch64.
	Kernel Need = "kernel"
	// CF is HDTP_CF_DOMAIN: two real Cloudflare tunnels built by
	// docs/demos/cloudflare-two-users.md, which no test may provision.
	CF Need = "cf"
	// HDTPCLI is the `hdtp` command of hdtp-identity, named by HDTP_CLI: the live intrusion battery
	// (`hdtp vectors intrude --against`), which is data in hdtp-identity and aimed at any host.
	// `make harness-hdtp-cli` builds it from the sibling checkout.
	HDTPCLI Need = "hdtp-cli"
	// CloudBattery is the Go conformance battery's checkout (batondeck/gateway/conformance), named
	// by HDTP_CLOUD_BATTERY: the one battery the cloud runs against staging, run here against a node.
	CloudBattery Need = "cloud-battery"
	// LocalCloud is batondeck's local cloud and its live-local runner (gateway/e2e/local-run.mjs),
	// named by HDTP_LOCAL_CLOUD (the gateway directory), with the WorkOS test pair its session
	// injection verifies (WORKOS_TEST_CLIENT_ID, WORKOS_TEST_API_KEY) and its built public/.
	LocalCloud Need = "local-cloud"
)

// Needs is every need.
var Needs = []Need{Docker, NodeImage, CaldavImage, Chrome, Kernel, CF, HDTPCLI, CloudBattery, LocalCloud}

// The environment variables the harness reads.
const (
	// LiveEnv turns live scenarios on. Without it Start skips and records nothing, which is what
	// keeps the hermetic tier hermetic.
	LiveEnv = "HDTP_HARNESS_LIVE"
	// ResultsEnv is the directory Start writes one <id>.json per scenario into.
	ResultsEnv = "HDTP_HARNESS_RESULTS"
	// KernelEnv names the guest kernel (Need Kernel).
	KernelEnv = "HDTP_HARNESS_KERNEL"
	// CFEnv names the Cloudflare domain (Need CF).
	CFEnv = "HDTP_CF_DOMAIN"
	// HDTPCLIEnv names the hdtp CLI (Need HDTPCLI).
	HDTPCLIEnv = "HDTP_CLI"
	// CloudBatteryEnv names the battery's directory (Need CloudBattery).
	CloudBatteryEnv = "HDTP_CLOUD_BATTERY"
	// LocalCloudEnv names batondeck's gateway directory (Need LocalCloud).
	LocalCloudEnv = "HDTP_LOCAL_CLOUD"
)

// Spec is one scenario.
type Spec struct {
	// ID is stable and unique: a letter for the family (F the fabric, S a suite, T a topology
	// that needs its own scaffolding) and a number. docs/harness-design.md is keyed by it.
	ID string
	// Name says what the scenario proves, in a line.
	Name string
	// Tier is the smallest tier that runs it.
	Tier Tier
	// Needs is everything it requires of the machine. A tier that provides all of them PROMISES
	// the scenario: if it then skips, the tier fails.
	Needs []Need
	// Timeout bounds the scenario's context, and it is what the tier's `go test -timeout` is
	// summed from.
	Timeout time.Duration
}

var idShape = regexp.MustCompile(`^[A-Z][0-9]+$`)

// Validate reports what is wrong with a spec, or nil.
func (s Spec) Validate() error {
	if !idShape.MatchString(s.ID) {
		return fmt.Errorf("id %q is not a letter and a number", s.ID)
	}
	if s.Name == "" {
		return fmt.Errorf("%s has no name", s.ID)
	}
	if !slices.Contains(Tiers, s.Tier) {
		return fmt.Errorf("%s has tier %q, not one of %v", s.ID, s.Tier, Tiers)
	}
	if len(s.Needs) == 0 {
		return fmt.Errorf("%s needs nothing: every live scenario needs something to run on (Docker, a Kernel, the local cloud)", s.ID)
	}
	for i, n := range s.Needs {
		if !slices.Contains(Needs, n) {
			return fmt.Errorf("%s needs %q, not one of %v", s.ID, n, Needs)
		}
		if slices.Contains(s.Needs[:i], n) {
			return fmt.Errorf("%s needs %s twice", s.ID, n)
		}
	}
	if s.Timeout <= 0 {
		return fmt.Errorf("%s has no timeout", s.ID)
	}
	return nil
}

// Provides is what running a tier supplies: its Makefile target builds the images, and the
// environment names a kernel or a Cloudflare domain or it does not. A scenario whose needs are all
// provided is promised by the tier.
func Provides(t Tier, getenv func(string) string) []Need {
	out := []Need{Docker, NodeImage}
	if t == Fabric {
		return out
	}
	out = append(out, Chrome)
	if t == PR {
		return out
	}
	out = append(out, CaldavImage)
	if getenv(KernelEnv) != "" {
		out = append(out, Kernel)
	}
	if getenv(CFEnv) != "" {
		out = append(out, CF)
	}
	if getenv(HDTPCLIEnv) != "" {
		out = append(out, HDTPCLI)
	}
	if getenv(CloudBatteryEnv) != "" {
		out = append(out, CloudBattery)
	}
	if getenv(LocalCloudEnv) != "" {
		out = append(out, LocalCloud)
	}
	return out
}

// Missing is the needs of s that provided does not cover.
func (s Spec) Missing(provided []Need) []Need {
	var out []Need
	for _, n := range s.Needs {
		if !slices.Contains(provided, n) {
			out = append(out, n)
		}
	}
	return out
}

// HowToProvide says what a person does to supply a need.
func HowToProvide(n Need) string {
	switch n {
	case Docker:
		return "start a Docker daemon"
	case NodeImage:
		return "make harness-image"
	case CaldavImage:
		return "make harness-image-caldav"
	case Chrome:
		return "install Google Chrome"
	case Kernel:
		return "make harness-kernel, then export " + KernelEnv + " (and an accelerated qemu-system-aarch64)"
	case CF:
		return "run docs/demos/cloudflare-two-users.md, then export " + CFEnv
	case HDTPCLI:
		return "make harness-hdtp-cli (a hdtp-identity checkout beside this one), or export " + HDTPCLIEnv + " naming a built hdtp"
	case LocalCloud:
		return "export " + LocalCloudEnv + " naming a batondeck gateway/ with e2e/local-run.mjs and a built public/, and WORKOS_TEST_CLIENT_ID and WORKOS_TEST_API_KEY"
	case CloudBattery:
		return "check batondeck out beside this repository (the Makefile then exports " + CloudBatteryEnv + "), or export it naming gateway/conformance"
	}
	return "unknown need"
}
