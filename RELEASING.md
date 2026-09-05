# Releasing, and verifying a release

Releases are tag-driven and every artifact is verifiable by someone who does not
trust us. That is the point: pact-gateway holds your identity keys, so "download
this binary" has to be checkable.

## Cutting a release

1. Update `CHANGELOG.md` — the release notes are extracted from its section for
   this version.
2. `make check` and `make harness` green.
3. Tag and push: `git tag v1.2.3 && git push origin v1.2.3`.

`.github/workflows/release.yml` then re-runs the gate, builds every platform with
`make dist`, generates a CycloneDX SBOM, attests build provenance and the SBOM via
Sigstore, and publishes the GitHub release. The workflow runs the *same* `make`
targets a maintainer runs locally, so CI has no private build path.

## Verifying a release you downloaded

**Checksum:**

```
shasum -a 256 -c SHA256SUMS --ignore-missing
```

**Provenance** — proves the binary was built by this workflow, from this
repository, at a specific commit, rather than on someone's laptop:

```
gh attestation verify pact-gateway_1.2.3_linux_amd64 --repo tech-sumit/pact-gateway
```

**Rebuild it yourself.** Builds are reproducible: `CGO_ENABLED=0` and `-trimpath`
mean no host libc and no embedded build paths. At the same tag, with the Go
toolchain from `go.mod`:

```
make dist VERSION=1.2.3
shasum -a 256 dist/pact-gateway_1.2.3_linux_amd64
```

That must equal the published checksum. Verified two consecutive clean builds
produce byte-identical output; a mismatch is a bug worth reporting.

**SBOM:** `sbom.cdx.json` (CycloneDX 1.6) lists the full dependency graph and is
itself attested, so it can be fed to a scanner without trusting the release page.

## What this does not prove

Provenance says *where a binary came from*, never that the source is good. It
means the artifact matches this repository at that commit — nothing about whether
the code is correct or the design sound. See [SECURITY.md](SECURITY.md) for what
has and has not been reviewed.
