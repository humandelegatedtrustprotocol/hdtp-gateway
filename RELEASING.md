# Releasing, and verifying a release

Releases are cut locally, by a maintainer, from a tag. There is no release workflow:
this repository has no CI, because the node depends on a private module that no runner
is given a key for. hdtp-gateway holds your identity keys, so "download this binary" has to
be checkable: the checksums are published, and anyone who can read this repository AND the
private identity module can rebuild a tag and compare.

## Cutting a release

1. Update `CHANGELOG.md` — the release notes are its section for this version.
2. The gate green on the commit being tagged: the pre-push hook runs it (`make check`
   on both engines, `make analyze`, `make sqlc-check`, `make fuzz`, `make harness`).
3. Tag and push: `git tag v1.2.3 && git push origin v1.2.3`.
4. Build every platform and the SBOM from that tag:

   ```
   make dist VERSION=1.2.3
   make sbom
   ```

5. Publish, with the notes taken from `CHANGELOG.md`:

   ```
   gh release create v1.2.3 --title v1.2.3 --notes-file <notes> \
     dist/hdtp-gateway_* dist/SHA256SUMS dist/sbom.cdx.json
   ```

## Verifying a release you downloaded

**Checksum:**

```
shasum -a 256 -c SHA256SUMS --ignore-missing
```

**Rebuild it yourself.** Builds are reproducible: `CGO_ENABLED=0` and `-trimpath`
mean no host libc and no embedded build paths. It needs read access to both private
repositories and the fetch settings of [CONTRIBUTING.md](CONTRIBUTING.md#the-identity-module)
(`make dist` does not set them). At the same tag, with the Go toolchain from `go.mod`:

```
make dist VERSION=1.2.3
shasum -a 256 dist/hdtp-gateway_1.2.3_linux_amd64
```

That must equal the published checksum. Verified two consecutive clean builds
produce byte-identical output; a mismatch is a bug worth reporting.

**SBOM:** `sbom.cdx.json` (CycloneDX 1.6) lists the full dependency graph.

## What this does not prove

There is no build-provenance or SBOM attestation: releases are built on a
maintainer's machine, so nothing binds a binary to a hosted build. A matching rebuild
is the check. And a matching rebuild says only that the artifact matches this
repository at that commit — nothing about whether the code is correct or the design
sound. See [SECURITY.md](https://github.com/humandelegatedtrustprotocol/.github/blob/main/SECURITY.md) for what has and has not been reviewed.
