# Releasing, and verifying a release

Releases are cut locally, by a maintainer, from a tag. There is no release workflow:
this repository has no CI, so a release is built where its gate runs, on the machine that
pushes ([CONTRIBUTING.md](CONTRIBUTING.md)). hdtp-gateway holds your identity keys, so
"download this binary" has to be checkable: the checksums are published, and anyone can
rebuild a tag and compare.

## Cutting a release

1. Update `CHANGELOG.md` — the release notes are its section for this version.
2. The gate green on the commit being tagged: the pre-push hook runs it (`make check`
   on both engines, `make analyze`, `make sqlc-check`, `make fuzz`, `make harness`).
3. Tag and push: `git tag v1.2.3 && git push origin v1.2.3`.
4. Build every platform and the SBOM from a fresh clone of that tag:

   ```
   dir=$(mktemp -d)/hdtp-gateway
   git clone --branch v1.2.3 https://github.com/humandelegatedtrustprotocol/hdtp-gateway.git "$dir"
   cd "$dir"
   make dist VERSION=1.2.3
   make sbom
   ```

   `make dist` refuses to build unless `git status --porcelain` is empty and HEAD is the commit
   `v1.2.3` names. Untracked files count: the go command stamps a binary built beside any of them
   `vcs.modified=true`, and that stamp changes the checksum. After building, it refuses unless every
   binary's build info (`go version -m`) records `vcs.modified=false` and that commit as
   `vcs.revision`. A working checkout usually holds something untracked, which is why the build is
   done in a fresh clone. `make release-check`, part of `make check`, runs `dist` against fixture
   repositories and shows each refusal and the clean build that passes.

   `make sbom` reads the repository through its own git library (cyclonedx-gomod), so run it in
   a checkout whose `.git` is a directory, which a clone is: a linked worktree, whose `.git` is a
   `gitdir:` file, fails with `reference not found`. The version it stamps on the main module is the
   tag on HEAD, or a pseudo-version when there is none.

5. Publish, with the notes taken from `CHANGELOG.md`:

   ```
   gh release create v1.2.3 --title v1.2.3 --notes-file <notes> \
     dist/hdtp-gateway_* dist/SHA256SUMS dist/sbom.cdx.json THIRD_PARTY_NOTICES
   ```

   `THIRD_PARTY_NOTICES` is the licence text of everything the binaries and the portal
   redistribute; `make notices-check`, in the gate, holds it to the dependency set.

## Verifying a release you downloaded

**Checksum:**

```
shasum -a 256 -c SHA256SUMS --ignore-missing
```

**Rebuild it yourself.** Builds are reproducible: `CGO_ENABLED=0` and `-trimpath`
mean no host libc and no embedded build paths. In a fresh clone of the tag, with the Go
toolchain from `go.mod`:

```
make dist VERSION=1.2.3
shasum -a 256 dist/hdtp-gateway_1.2.3_linux_amd64
go version -m dist/hdtp-gateway_1.2.3_linux_amd64 | grep vcs
```

The checksum must equal the published one, and the published binary's `go version -m` must
show `vcs.modified=false` and the tag's commit. A mismatch is a bug worth reporting.

**SBOM:** `sbom.cdx.json` (CycloneDX 1.6) lists the full dependency graph.

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

The published releases are left as they are. The next release, built under the checks above,
supersedes them.

## What this does not prove

There is no build-provenance or SBOM attestation: releases are built on a
maintainer's machine, so nothing binds a binary to a hosted build. A matching rebuild
is the check. And a matching rebuild says only that the artifact matches this
repository at that commit — nothing about whether the code is correct or the design
sound. Nothing here has had independent cryptographic review
([`docs/threat-model.md`](docs/threat-model.md)); a vulnerability is reported as
[`SECURITY.md`](SECURITY.md) says.
