#!/usr/bin/env bash
# Builds the limits sidecar (cmd/hdtp-limitd, SPEC §5.7) for each PLATFORM as a release asset beside
# the node's binaries: OUTDIR/hdtp-limitd_VERSION_<os>_<arch>. `make dist` runs it after
# `make limitd-vendor`, in the checkout being released.
#
#   scripts/limitd-dist.sh VERSION OUTDIR PLATFORM...
#
# The crates are the vendored ones (.build/limitd-vendor), read offline, as the image build reads
# them. One Rust builds every platform: the Dockerfile's `FROM rust:<version>-alpine AS limitd` image.
#   linux/<arch>  in that image under `docker run --platform linux/<arch>`: Alpine's Rust targets
#                 musl and links statically, the binary the image ships.
#   darwin/<arch> natively, `cargo build --target <arch>-apple-darwin`. Refused, naming the rustup
#                 command, when that target is not installed, and refused when the host's rustc is
#                 not the image's version.
# The checkout's path is remapped to /hdtp-gateway (--remap-path-prefix), in the container as on the
# host, and on the host the standard library's source to /rustc/<commit>, so no build path of this
# machine is in a binary. Every platform is checked before any is
# built. scripts/release-check-test.sh runs it against stubs of docker, cargo, rustup and rustc.
set -euo pipefail

die() { echo "limitd-dist: $*" >&2; exit 1; }

[ $# -ge 3 ] || die "usage: $0 VERSION OUTDIR PLATFORM..."
version=$1 out=$2
shift 2

limitd=cmd/hdtp-limitd
vendor=.build/limitd-vendor
image=$(sed -n 's/^FROM \(rust:[^ ]*\) AS limitd$/\1/p' Dockerfile)
[ -n "$image" ] || die "the Dockerfile has no 'FROM rust:<version>-alpine AS limitd' line to build with"
rust=${image#rust:}
rust=${rust%-alpine}
[ -f "$vendor/config.toml" ] || die "no $vendor/config.toml: run make limitd-vendor first"
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
here=$(pwd -P)

triple() { case $1 in arm64) echo aarch64-apple-darwin ;; amd64) echo x86_64-apple-darwin ;; *) return 1 ;; esac; }

for p in "$@"; do
  os=${p%/*} arch=${p#*/}
  case $os in
  linux) ;;
  darwin)
    t=$(triple "$arch") || die "$p: no Rust target for darwin/$arch"
    rustup target list --installed | grep -qx "$t" || die "$p: the Rust target $t is not installed: rustup target add $t"
    rustc --version | grep -q "^rustc $rust\." ||
      die "$p: the host's Rust is '$(rustc --version)', not $rust, the Dockerfile's $image; one Rust builds every platform"
    ;;
  *) die "$p: no recipe for $os" ;;
  esac
done

cfg=$(mktemp "${TMPDIR:-/tmp}/limitd-dist.XXXXXX")
trap 'rm -f "$cfg"' EXIT
sed "s#^directory = .*#directory = \"$here/$vendor/crates\"#" "$vendor/config.toml" > "$cfg"

for p in "$@"; do
  os=${p%/*} arch=${p#*/}
  name=hdtp-limitd_${version}_${os}_${arch}
  echo "building $out/$name"
  case $os in
  linux)
    docker run --rm --platform "linux/$arch" -v "$here:/hdtp-gateway:ro" -v "$out:/out" "$image" sh -ec "
      mkdir /build && tar -C /hdtp-gateway/$limitd --exclude=./target -cf - . | tar -C /build -xf -
      cd /build
      sed 's#^directory = .*#directory = \"/hdtp-gateway/$vendor/crates\"#' /hdtp-gateway/$vendor/config.toml > .cargo/config.toml
      RUSTFLAGS='--remap-path-prefix=/build=/hdtp-gateway/$limitd' cargo build --release --locked --offline
      cp target/release/hdtp-limitd /out/$name"
    ;;
  darwin)
    t=$(triple "$arch")
    # With the rust-src component installed, the standard library's paths are the toolchain's own
    # directory under the home directory: they go back to /rustc/<commit>, as an official build names them.
    std="$(rustc --print sysroot)/lib/rustlib/src/rust=/rustc/$(rustc -vV | sed -n 's/^commit-hash: //p')"
    RUSTFLAGS="--remap-path-prefix=$here=/hdtp-gateway --remap-path-prefix=$std" cargo build --release --locked --offline \
      --config "$cfg" --target "$t" --manifest-path "$limitd/Cargo.toml"
    cp "$limitd/target/$t/release/hdtp-limitd" "$out/$name"
    ;;
  esac
done
