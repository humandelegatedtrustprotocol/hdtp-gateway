# Testing

## The scenario harness

`harness/` is a separate Go module that stands real nodes up in containers (and, for S8, a
QEMU guest), drives the portal in a real Chrome, and talks to the node over real mTLS. Its design,
its scenario table and what each tier measured are in `docs/harness-design.md`; this section is
how to use it and how to add to it.

### Tiers

| Command | Runs | Needs on the machine |
|---|---|---|
| `make harness` | the hermetic tier: every package's unit tests against recorders, the registry, image and port guards, `go vet`. No scenario runs: each live test skips without `PACT_HARNESS_LIVE`. The `pre-push` hook runs this on every push. | Go |
| `make harness-live` | the fabric tier, F1–F5 | Docker |
| `make harness-pr` | fabric + S2, S9 (`PACT_PREPUSH_LIVE=1 git push` runs it too) | Docker, Chrome |
| `make harness-nightly` | every scenario (`PACT_PREPUSH_LIVE=full git push`) | Docker, Chrome; S8 needs `PACT_HARNESS_KERNEL`, T7 needs `PACT_CF_DOMAIN` |

Each target builds the images it promises (`harness-image`, and for nightly
`harness-image-caldav` and `harness-shaper`) and then runs `go run ./cmd/harness run -tier …`
from `harness/`. That command:

1. reads the registry from the source (below) and prints each scenario as **promised** — the
   tier provides everything it needs — or **NOT PROMISED**, with what would provide it;
2. runs `go test -v -count=1` on exactly those tests, with a `-timeout` summed from their specs;
3. judges: a promised scenario must PASS. SKIPPED fails the tier just as FAIL does, and so does
   a promised scenario that left no result. A scenario the tier did not promise may skip.

Other forms: `go run ./cmd/harness run -id S11,S13` runs named scenarios and promises all their
needs; `-n` prints the plan and stops; `-results DIR` keeps the results somewhere you choose.
`go run ./cmd/harness list` prints the registry as JSON, and `list -doc` the table in
`docs/harness-design.md` §4 (`-doc -write` puts it there).

### What a scenario may need

| Need | Provided by | A tier provides it |
|---|---|---|
| `docker` | a Docker daemon (checked through `preflight`) | every live tier |
| `node-image` | `make harness-image` | every live tier |
| `chrome` | Google Chrome, launched headless by the portal driver | pr, nightly |
| `caldav-image` | `make harness-image-caldav` | nightly |
| `kernel` | `make harness-kernel`, then `export PACT_HARNESS_KERNEL=<path it prints>`; an accelerated `qemu-system-aarch64` | nightly, when the variable is set |
| `cf` | the rig `docs/demos/cloudflare-two-users.md` builds, then `export PACT_CF_DOMAIN=<domain>` | nightly, when the variable is set |

### Results

Each scenario writes `<id>.json` into `PACT_HARNESS_RESULTS` (`harness run` sets it to a fresh
directory and prints where):

```json
{ "id": "S2", "name": "…", "test": "TestPairingAndMessagingEndToEnd",
  "verdict": "PASS | FAIL | SKIPPED", "reason": "why, for SKIPPED and FAIL", "ms": 2100 }
```

and `harness run` writes `summary.json` beside them: `{ run, repo, tier, cases: [{ id, name,
promised, verdict, reason, ms, ok }] }`. With `PACT_HARNESS_ARTIFACTS=<dir>` every container's
log is collected there at teardown.

### Adding a scenario

One file, `harness/scenario/<what>_live_test.go`, and one command:

```go
package scenario

import (
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/registry"
)

// S16 — what it proves, and which defect or SPEC section it holds.
func TestSomethingEndToEnd(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S16", Name: "what it proves, in a line", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 10 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	// alice.Owner is her owner MCP, alice.Portal her signed-in portal session, alice.Pin what a
	// caller holds of her. w.Paired(ctx, "") gives a node with an approved contact instead.
	_ = alice
}
```

That is the only file you write. One command then regenerates the scenario table in
`docs/harness-design.md` §4: `cd harness && go run ./cmd/harness list -doc -write`
(`registry_test.go` fails until you do).

What the hermetic tier holds you to, so these fail at `make harness`, not in a nightly run:

- **The spec is a literal in the test that runs it.** `registry.Scan` reads it from the source
  (that is how the tiers, the list and the doc table see it), so every field is a literal: a
  string, `registry.<Tier>`, `registry.<Need>`s, and `N * time.Minute`. The id is a letter and
  a number, unique; a `*live_test.go` Test without a spec is an error.
- **No hand-picked host port.** `World.Node` takes them from `fabric.FreePort`; `ports_test.go`
  fails on a literal like `"18680"`.
- **No image named outside `harness/images`**, and no upstream image without a digest
  (`images_test.go`).
- **Every account is certified.** `World.Node` does it (`topology.Certify`); a file that creates
  an account and never has a wallet certify it fails `wallet_test.go`.

And what no test can hold, so it is on you: wait for a condition with a deadline, never a fixed
sleep; name what you build through the World (`w.Fab.Name`), so two runs never collide; and do
not `t.Skip` inside a scenario for a missing tool — declare it as a need, so the tier knows
whether it promised it.
