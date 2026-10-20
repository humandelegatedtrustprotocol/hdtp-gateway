# Releasing, and verifying a release

Releases are cut locally, by a maintainer, from a tag. There is no release workflow:
this repository has no CI, so a release is built where its gate runs, on the machine that
pushes ([CONTRIBUTING.md](CONTRIBUTING.md)). hdtp-gateway holds your identity keys, so
"download this binary" has to be checkable: the checksums are published, and anyone can
rebuild a tag and compare.

## Cutting a release

1. Update `CHANGELOG.md` — the release notes are its section for this version — and
   `compose.yaml`'s image to the version (`ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:1.2.3`
   in both services): `make image` refuses a version `compose.yaml` does not pull.
2. The gate green on the commit being tagged: the pre-push hook runs it (`make check`
   on both engines, `make analyze`, `make sqlc-check`, `make fuzz`, `make harness`).
3. Tag and push, with an annotated tag whose message is one line naming the release:
   `git tag -a v1.2.3 -m "hdtp-gateway 1.2.3 — <summary>; CHANGELOG.md has the notes" && git push origin v1.2.3`.
   v0.1.0 to v0.1.2 are annotated tags; v0.1.3 was tagged lightweight, on the merge commit `beb206c`,
   and stays as it is, since a published tag is never moved. `scripts/release-check.sh` resolves the
   tag to its commit (`v1.2.3^{commit}`), and the fixtures `make release-check` builds are annotated.
4. Build every platform and the SBOM from a fresh clone of that tag:

   ```
   dir=$(mktemp -d)/hdtp-gateway
   git clone --branch v1.2.3 https://github.com/humandelegatedtrustprotocol/hdtp-gateway.git "$dir"
   cd "$dir"
   make dist VERSION=1.2.3
   make sbom VERSION=1.2.3
   ```

   `make dist` builds the node (`dist/hdtp-gateway_*`) and its limits sidecar
   (`dist/hdtp-limitd_*`) for the four platforms, and `SHA256SUMS` over both. The sidecar is Rust,
   built from the crates `make limitd-vendor` lays out (fetched over the network, into the ignored
   `.build/`) by `scripts/limitd-dist.sh`: the Linux ones in the Dockerfile's Rust image
   (`rust:1.92-alpine`) under `docker run --platform`, so it needs Docker, and the macOS ones on
   the host, so it needs that Rust version and both darwin targets
   (`rustup target add x86_64-apple-darwin aarch64-apple-darwin`). A missing darwin target or
   another host Rust is refused, naming it, before any sidecar is built.

   `make dist` refuses to build unless `git status --porcelain` is empty and HEAD is the commit
   `v1.2.3` names. Untracked files count: the go command stamps a binary built beside any of them
   `vcs.modified=true`, and that stamp changes the checksum. After building, it refuses unless every
   binary's build info (`go version -m`) records `vcs.modified=false` and that commit as
   `vcs.revision`; that check reads Go build info, so it is the node's binaries alone. A working
   checkout usually holds something untracked, which is why the build is
   done in a fresh clone. `make sbom` holds to the same tree check. `make release-check`, part of `make check`, runs `dist` against fixture
   repositories and shows each refusal and the clean build that passes.

   `make sbom` reads the repository through its own git library (cyclonedx-gomod), so run it in
   a checkout whose `.git` is a directory, which a clone is: a linked worktree, whose `.git` is a
   `gitdir:` file, fails with `reference not found`. The version it stamps on the main module is the
   tag on HEAD, or a pseudo-version when there is none.

5. Build and push the image, from the same fresh clone, after `docker login ghcr.io` with a
   token that may write the organisation's packages:

   ```
   make image VERSION=1.2.3 PUSH=1
   docker buildx imagetools inspect ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:1.2.3
   ```

   `make image` builds the `Dockerfile` for linux/amd64 and linux/arm64 with the crates
   `make limitd-vendor` lays out and `--build-arg VERSION=1.2.3`, which the binary's `main.version`
   is stamped with, and tags it `1.2.3` and `latest`. It holds to `make dist`'s tree check and
   refuses a version `compose.yaml` does not pull; `make release-check` runs it against fixtures with
   a stubbed docker. The platform the machine is not is built under emulation: on an arm64 Mac
   (2026-10-20, `--no-cache`, which keeps BuildKit's cache mounts of Go modules and builds) both
   platforms took 372 s, the amd64 Go build 297.5 s and the amd64 sidecar build 137.8 s of it, the
   two running side by side; natively, on arm64, they took 47.9 s and 15.4 s. Without `PUSH=1` the image
   is kept in Docker's own store. The image carries the OCI labels `source` (this repository, which
   links the package to it), `version`, `licenses` and `description`. The first push creates the
   package private; making it public is the organisation owner's. Put the manifest digest
   `imagetools inspect` prints in the release notes.

6. Publish, with the notes taken from `CHANGELOG.md`:

   ```
   gh release create v1.2.3 --title v1.2.3 --notes-file <notes> \
     dist/hdtp-gateway_* dist/hdtp-limitd_* dist/SHA256SUMS dist/sbom.cdx.json THIRD_PARTY_NOTICES
   ```

   `THIRD_PARTY_NOTICES` is the licence text of everything the binaries and the portal
   redistribute, the Go modules taken for every platform in the Makefile's `PLATFORMS`;
   `make notices-check`, in the gate, holds it to that list and to the dependency set. The files
   attached to v0.1.5 and before were made for the host alone and lack the eight modules only the
   Linux binaries link (`github.com/vishvananda/netlink` among them); they are left as they were
   published.

## Verifying a release you downloaded

**Checksum:**

```
shasum -a 256 -c SHA256SUMS --ignore-missing
```

**Rebuild it yourself.** The node's builds are reproducible: `CGO_ENABLED=0` and `-trimpath`
mean no host libc and no embedded build paths. `make dist` builds the limits sidecar too, so in a
fresh clone of the tag it needs, beside the Go toolchain from `go.mod`, Docker (the Linux
sidecars are built in the `rust:1.92-alpine` image), Rust 1.92 on the host and its two darwin
targets (`rustup target add x86_64-apple-darwin aarch64-apple-darwin`):

```
make dist VERSION=1.2.3
shasum -a 256 dist/hdtp-gateway_1.2.3_linux_amd64
go version -m dist/hdtp-gateway_1.2.3_linux_amd64 | grep vcs
```

The checksum must equal the published one, and the published binary's `go version -m` must
show `vcs.modified=false` and the tag's commit. A mismatch is a bug worth reporting. The Linux
sidecars rebuilt from another checkout were byte-identical; the macOS sidecars built from a
checkout at another path differ in the Mach-O `LC_UUID` and, on arm64, the code signature over it,
so they do not match the published checksum ([What this does not prove](#what-this-does-not-prove)).

To check the node's binaries alone, Go is all it takes: in a fresh clone of the tag, build each
platform as `make dist` does, here linux/amd64, and compare as above:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true \
  -ldflags "-s -w -X main.version=1.2.3" -o hdtp-gateway_1.2.3_linux_amd64 ./cmd/hdtp-gateway
```

Run in two fresh clones at different paths, this line gave the same checksum and
`vcs.modified=false` in both (2026-10-16, a local tag, linux/amd64).

**The image:** its binary prints the release (`docker run --rm ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:1.2.3 version`
prints `hdtp-gateway 1.2.3`), and the release notes carry the manifest digest it was pushed under,
which `docker buildx imagetools inspect` shows for the tag. The image is not reproducible byte for
byte: of the `Dockerfile`'s three base images only the Go one is named by digest; `rust:1.92-alpine`
and `gcr.io/distroless/static-debian12:nonroot` are named by tag, so a rebuild later may start from
other bytes. What ties it to the tag is that it was built by `make image` from a fresh clone of it.

**SBOM:** `sbom.cdx.json` (CycloneDX 1.6) is the node's: the Go modules `cmd/hdtp-gateway` links
(`cyclonedx-gomod app`). It does not list the limits sidecar's Rust crates; their list is
`cmd/hdtp-limitd/Cargo.lock` at the tag.

## v0.1.0, v0.1.1 and v0.1.2

These three releases were built before `make dist` checked the tree, from a tree the go command
saw as modified, so a rebuild from a clean checkout of the tag does not match them. Measured on
2026-10-10 against the published assets:

- All twelve binaries (four platforms each) match their release's `SHA256SUMS`.
- Every one of them records `vcs.modified=true`. Each records its tag's commit as
  `vcs.revision`, and each was built with go1.26.6 (v0.1.0, v0.1.1) or go1.26.9 (v0.1.2).
- For linux/amd64 only: a fresh clone of each tag, built with the `dist` flags and one empty
  untracked file present, gives exactly the published checksum. The same clone with no
  untracked file gives a different one. The untracked file is the only difference between the
  two builds and is not compiled; their build info differs in two lines, `vcs.modified=true` and
  the main module's version, `v0.1.2+dirty` against `v0.1.2` (compared for v0.1.2). The other
  three platforms were not rebuilt.

The published releases are left as they are. v0.1.3, the first release built under the checks
above, supersedes them.

## What this does not prove

There is no build-provenance or SBOM attestation: releases are built on a
maintainer's machine, so nothing binds a binary to a hosted build. The limits sidecar's binaries
carry no build info, so nothing checks them against the tag the way `release-check.sh binaries`
checks the node's, and a rebuild of them is not held to the published checksum by any check.
Measured once, on 2026-10-16 (host rustc 1.92.0 and the `rust:1.92-alpine` image): the Linux
sidecars built by `make dist` from two checkouts at different paths were byte-identical; the
macOS ones were identical when rebuilt at the same path, and from a checkout at another path
differed only in the Mach-O `LC_UUID` (16 bytes) and, on arm64, the ad-hoc code signature that
covers it (32 bytes), every string in them the same. A macOS sidecar rebuilt elsewhere does not
match the published checksum for that reason. The image is named by tag, not by digest, so an
image published later under the same tag may build other bytes. A matching rebuild
is the check. And a matching rebuild says only that the artifact matches this
repository at that commit — nothing about whether the code is correct or the design
sound. Nothing here has had independent cryptographic review
([`docs/threat-model.md`](docs/threat-model.md)); a vulnerability is reported as
[`SECURITY.md`](SECURITY.md) says.
