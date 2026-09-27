// Package images names every container image the harness runs, once.
//
// Two kinds live here. The first three are built on this machine from this repository by `make`
// (the product, the product with a pinned calendar server, and the traffic shaper), so they are
// named by a local tag. Everything else is an upstream image pulled from a registry, and those
// are pinned by DIGEST: a tag like `:latest` is a promise the registry can break between two runs,
// and a scenario that fails because an upstream moved looks exactly like a scenario that found a
// defect. The digests were measured with `docker image inspect --format '{{.RepoDigests}}'` on
// 2026-09-27; the comment beside each says what the reference was before and when that image was
// built, so a bump is a deliberate edit rather than a surprise.
//
// No other file in this module may name an image (images_test.go holds that).
package images

import (
	"cmp"
	"os"
)

// Node is the product, built from the repo's own Dockerfile by `make harness-image`, under the tag
// PACT_HARNESS_IMAGE names (the Makefile's HARNESS_IMAGE), or pact-gateway:harness. A tag of one's
// own is what lets two worktrees on one machine run live tiers at once without one testing the
// other's binary, and what lets a mutation check run a deliberately broken build beside the real one.
var Node = cmp.Or(os.Getenv("PACT_HARNESS_IMAGE"), "pact-gateway:harness")

// Built locally by the Makefile.
const (
	// Caldav is the -full image plus a pinned caldav-mcp, built by `make harness-image-caldav`.
	Caldav = "pact-gateway:harness-caldav"
	// Shaper is Alpine with iproute2 (tc) already installed; fabric builds it on demand from
	// ShaperDockerfile, and `make harness-shaper` builds it ahead of a run.
	Shaper = "pact-harness-shaper:1"
)

// ShaperDockerfile is the one recipe for Shaper. It must ship tc rather than install it: the shaper
// runs inside the target's network namespace and cannot reach a package mirror through a partition
// it just created.
const ShaperDockerfile = "FROM " + Alpine + "\nRUN apk add --no-cache iproute2\n"

// Pulled from a registry, pinned by digest.
const (
	// Alpine was `alpine:3.20` (built 2026-04-16). The tag is kept for the reader; the digest is
	// what Docker resolves.
	Alpine = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	// Socat was the untagged `alpine/socat` (latest, built 2026-08-22).
	Socat = "alpine/socat@sha256:3d9e7966201dd3a065df591020a09fd3c70845de7e7086e3531ea69db774406b"
	// Curl was `curlimages/curl:latest` (built 2026-06-24).
	Curl = "curlimages/curl@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13"
	// Pebble was `ghcr.io/letsencrypt/pebble:latest` (built 2026-04-20).
	Pebble = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
	// CoreDNS was `coredns/coredns:latest` (built 2026-08-19).
	CoreDNS = "coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
	// Radicale was `tomsquest/docker-radicale:latest` (built 2026-08-25).
	Radicale = "tomsquest/docker-radicale@sha256:e2ef8624b2156ada47489223df12575406d625c96725f03cfc4dc890e3eda400"
	// Frps was `snowdreamtech/frps:latest` (frp 0.71.0, built 2026-08-14).
	Frps = "snowdreamtech/frps@sha256:a98c472999f1a784b53cd6b7ed8a7e23b7a28ceda7aa7943e5313072175bfaae"
)

// Local lists the images built here; Pulled lists the ones pinned by digest. The guard in
// images_test.go reads both, so an image added to the constants and not to a list fails it.
var (
	Local  = []string{Node, Caldav, Shaper}
	Pulled = []string{Alpine, Socat, Curl, Pebble, CoreDNS, Radicale, Frps}
)
