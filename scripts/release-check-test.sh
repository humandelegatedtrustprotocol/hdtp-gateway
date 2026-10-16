#!/usr/bin/env bash
# Runs this checkout's `make dist` against fixture repositories, with no network and nothing
# published: refused on a dirty tree (untracked file, modified file), on an untagged HEAD and on a
# HEAD tagged with another version; passing on a clean checkout of the tag, with binaries that
# record vcs.modified=false. Then the binary check alone: a build from a modified tree, a build
# with no VCS stamp and a build of another commit are each refused. The limits sidecar's part of
# dist (limitd-vendor, scripts/limitd-dist.sh) runs against stubs of cargo, docker, rustup and
# rustc, which record what they were asked: the assets it writes and SHA256SUMS lists, and its
# refusals of a darwin target that is not installed and of another Rust. Run by `make check`.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
makefile=$root/Makefile
check=$root/scripts/release-check.sh

# A hook in a linked worktree exports GIT_DIR and friends; the fixtures are repositories of their own.
while IFS= read -r v; do unset "$v"; done < <(env | sed -n 's/^\(GIT_[A-Za-z_]*\)=.*/\1/p')
export GOWORK=off GOFLAGS='' GOTOOLCHAIN=local GOPROXY=off GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null

tmp=$(mktemp -d "${TMPDIR:-/tmp}/release-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail=0
pass() { echo "release-check: ok   $1"; }
bad() { echo "release-check: FAIL $1" >&2; fail=1; }

g() { git -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false -c tag.gpgSign=false "$@"; }

goline=$(go env GOVERSION | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')

fixture() {
  local dir=$tmp/$1
  mkdir -p "$dir/cmd/hdtp-gateway" "$dir/cmd/hdtp-limitd"
  printf 'module example.invalid/fixture\n\ngo %s\n' "$goline" > "$dir/go.mod"
  printf 'package main\n\nvar version string\n\nfunc main() { println(version) }\n' > "$dir/cmd/hdtp-gateway/main.go"
  printf '[package]\nname = "hdtp-limitd"\n' > "$dir/cmd/hdtp-limitd/Cargo.toml"
  printf 'FROM rust:1.92-alpine AS limitd\n' > "$dir/Dockerfile"
  printf '/dist/\n/.build/\n' > "$dir/.gitignore"
  (cd "$dir" && g init -q && g add -A && g commit -q -m fixture && g tag -a v9.9.9 -m v9.9.9)
  echo "$dir"
}

# The sidecar's toolchain, stubbed: each records its arguments in $tmp/stub.log.
mkdir -p "$tmp/stub"
cat > "$tmp/stub/cargo" <<'STUB'
#!/bin/sh
echo "cargo $* RUSTFLAGS=$RUSTFLAGS" >> "$STUB_LOG"
case $1 in
vendor) printf '[source.vendored-sources]\ndirectory = ".build/limitd-vendor/crates"\n' ;;
build)
  t= m=
  while [ $# -gt 0 ]; do case $1 in --target) t=$2; shift ;; --manifest-path) m=$2; shift ;; esac; shift; done
  mkdir -p "$(dirname "$m")/target/$t/release" && echo "stub $t" > "$(dirname "$m")/target/$t/release/hdtp-limitd" ;;
esac
STUB
cat > "$tmp/stub/docker" <<'STUB'
#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
out= prev=
for a in "$@"; do [ "$prev" = -v ] && case $a in *:/out) out=${a%:/out} ;; esac; prev=$a; done
eval "script=\${$#}"
name=$(printf '%s\n' "$script" | sed -n 's#.*cp target/release/hdtp-limitd /out/\([^ ]*\).*#\1#p')
echo "stub linux" > "$out/$name"
STUB
printf '#!/bin/sh\nprintf "%%s\\n" $STUB_TARGETS\n' > "$tmp/stub/rustup"
cat > "$tmp/stub/rustc" <<'STUB'
#!/bin/sh
case $1 in
--version) echo "rustc $STUB_RUSTC (stub)" ;;
--print) echo /stub/sysroot ;;
-vV) echo "commit-hash: stubhash" ;;
esac
STUB
chmod +x "$tmp/stub/"*
export STUB_LOG=$tmp/stub.log STUB_TARGETS="aarch64-apple-darwin x86_64-apple-darwin" STUB_RUSTC=1.92.0

dist() {
  : > "$STUB_LOG"
  PATH=$tmp/stub:$PATH make -s -C "$1" -f "$makefile" dist VERSION=9.9.9 PLATFORMS="${2:-linux/amd64}" >"$tmp/out" 2>&1
}

expect_refused() {
  local name=$1 dir=$2 why=$3
  if dist "$dir"; then
    bad "$name: dist built"
  elif ! grep -q "$why" "$tmp/out"; then
    bad "$name: refused, but not for '$why':"; cat "$tmp/out" >&2
  elif [ -e "$dir/dist" ]; then
    bad "$name: refused, but after writing dist/"
  else
    pass "$name: refused"
  fi
}

# The control: a clean checkout of the tag builds, and its binary records the tag's commit, unmodified.
d=$(fixture clean)
if dist "$d"; then
  if go version -m "$d/dist/hdtp-gateway_9.9.9_linux_amd64" | grep -qx "[[:space:]]*build[[:space:]]vcs.modified=false" &&
    grep -q hdtp-gateway_9.9.9_linux_amd64 "$d/dist/SHA256SUMS"; then
    pass "clean tagged tree: built"
  else
    bad "clean tagged tree: built, but the binary or SHA256SUMS is wrong"
  fi
  # The sidecar beside it: vendored, built in the Dockerfile's Rust image for that platform, and in
  # SHA256SUMS.
  if [ -s "$d/dist/hdtp-limitd_9.9.9_linux_amd64" ] && grep -q hdtp-limitd_9.9.9_linux_amd64 "$d/dist/SHA256SUMS" &&
    grep -q '^cargo vendor --locked --manifest-path cmd/hdtp-limitd/Cargo.toml' "$STUB_LOG" &&
    grep -q '^docker run --rm --platform linux/amd64 .* rust:1.92-alpine ' "$STUB_LOG"; then
    pass "clean tagged tree: the linux sidecar built in the image's Rust and summed"
  else
    bad "clean tagged tree: the sidecar asset, its sum or its build is wrong:"; cat "$STUB_LOG" "$d/dist/SHA256SUMS" >&2
  fi
else
  bad "clean tagged tree: refused:"; cat "$tmp/out" >&2
fi

# darwin: natively, for the target, offline over the vendored crates, the checkout's path remapped.
d=$(fixture darwin)
if dist "$d" darwin/arm64; then
  if [ -s "$d/dist/hdtp-limitd_9.9.9_darwin_arm64" ] && grep -q hdtp-limitd_9.9.9_darwin_arm64 "$d/dist/SHA256SUMS" &&
    grep -q "^cargo build --release --locked --offline --config .* --target aarch64-apple-darwin .*RUSTFLAGS=--remap-path-prefix=[^ ]*/darwin=/hdtp-gateway --remap-path-prefix=/stub/sysroot/lib/rustlib/src/rust=/rustc/stubhash$" "$STUB_LOG"; then
    pass "darwin sidecar: built for its target with the checkout's and the standard library's paths remapped, and summed"
  else
    bad "darwin sidecar: the asset, its sum or its build is wrong:"; cat "$STUB_LOG" >&2
  fi
else
  bad "darwin sidecar: refused:"; cat "$tmp/out" >&2
fi
d=$(fixture notarget)
if STUB_TARGETS=aarch64-apple-darwin dist "$d" darwin/amd64; then
  bad "darwin target not installed: dist built"
elif ! grep -q "rustup target add x86_64-apple-darwin" "$tmp/out"; then
  bad "darwin target not installed: refused, but not naming the rustup command:"; cat "$tmp/out" >&2
else
  pass "darwin target not installed: refused, naming rustup target add"
fi
d=$(fixture otherrust)
if STUB_RUSTC=1.91.1 dist "$d" darwin/arm64; then
  bad "another host Rust: dist built"
elif ! grep -q "not 1.92, the Dockerfile's rust:1.92-alpine" "$tmp/out"; then
  bad "another host Rust: refused, but not for the version:"; cat "$tmp/out" >&2
else
  pass "another host Rust: refused"
fi

d=$(fixture untracked); touch "$d/stray"
expect_refused "untracked file" "$d" "not clean"

d=$(fixture modified); echo '// edit' >> "$d/cmd/hdtp-gateway/main.go"
expect_refused "modified tracked file" "$d" "not clean"

d=$(fixture untagged); (cd "$d" && g commit -q --allow-empty -m later)
expect_refused "HEAD past the tag" "$d" "not v9.9.9"

d=$(fixture othertag); (cd "$d" && g tag -d v9.9.9 >/dev/null && g tag -a v9.9.8 -m v9.9.8)
expect_refused "HEAD tagged with another version" "$d" "no tag v9.9.9"

# The tree changing while dist builds: a `go` that leaves a stray file before building. The tree
# check has passed by then, so only dist's check of the binaries can refuse.
mkdir -p "$tmp/gostub"
realgo=$(command -v go)
cat > "$tmp/gostub/go" <<STUB
#!/bin/sh
[ "\$1" = build ] && touch stray
exec "$realgo" "\$@"
STUB
chmod +x "$tmp/gostub/go"
d=$(fixture duringbuild)
if PATH=$tmp/gostub:$PATH dist "$d"; then
  bad "tree modified during the build: dist passed"
elif ! grep -q "vcs.modified=false" "$tmp/out"; then
  bad "tree modified during the build: refused, but not by the binary check:"; cat "$tmp/out" >&2
else
  pass "tree modified during the build: refused"
fi

# sbom is a release asset too: refused on a dirty tree before it runs its tool (GOPROXY=off, so a
# check that let it through fails on the fetch, not on "not clean").
d=$(fixture sbom); touch "$d/stray"
if make -s -C "$d" -f "$makefile" sbom VERSION=9.9.9 >"$tmp/out" 2>&1; then
  bad "sbom on an untracked file: ran"
elif ! grep -q "not clean" "$tmp/out"; then
  bad "sbom on an untracked file: failed, but not for 'not clean':"; cat "$tmp/out" >&2
else
  pass "sbom on an untracked file: refused"
fi

# The binary check on builds dist would not make, each in a tree that is otherwise a clean tag.
d=$(fixture binaries)
build() { (cd "$d" && CGO_ENABLED=0 go build -trimpath "$@" -o "$tmp/bin" ./cmd/hdtp-gateway); }
refuse_bin() {
  if (cd "$d" && "$check" binaries 9.9.9 "$tmp/bin") >"$tmp/out" 2>&1; then
    bad "$1: binary check passed"
  elif ! grep -q "$2" "$tmp/out"; then
    bad "$1: refused, but not for '$2':"; cat "$tmp/out" >&2
  else
    pass "$1: binary refused"
  fi
}
build
if (cd "$d" && "$check" binaries 9.9.9 "$tmp/bin") >"$tmp/out" 2>&1; then
  pass "binary of the clean tag: accepted"
else
  bad "binary of the clean tag: refused:"; cat "$tmp/out" >&2
fi
touch "$d/stray"; build; rm "$d/stray"
refuse_bin "binary built with an untracked file present" "vcs.modified=false"
build -buildvcs=false
refuse_bin "binary built without VCS stamping" "vcs.modified=false"
(cd "$d" && g commit -q --allow-empty -m later); build; (cd "$d" && g reset -q --hard v9.9.9)
refuse_bin "binary of another commit" "vcs.revision="

exit $fail
