#!/usr/bin/env bash
# Runs this checkout's `make dist` against fixture repositories, with no network and nothing
# published: refused on a dirty tree (untracked file, modified file), on an untagged HEAD and on a
# HEAD tagged with another version; passing on a clean checkout of the tag, with binaries that
# record vcs.modified=false. Then the binary check alone: a build from a modified tree, a build
# with no VCS stamp and a build of another commit are each refused. Run by `make check`.
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
  mkdir -p "$dir/cmd/hdtp-gateway"
  printf 'module example.invalid/fixture\n\ngo %s\n' "$goline" > "$dir/go.mod"
  printf 'package main\n\nvar version string\n\nfunc main() { println(version) }\n' > "$dir/cmd/hdtp-gateway/main.go"
  printf '/dist/\n' > "$dir/.gitignore"
  (cd "$dir" && g init -q && g add -A && g commit -q -m fixture && g tag -a v9.9.9 -m v9.9.9)
  echo "$dir"
}

dist() { make -s -C "$1" -f "$makefile" dist VERSION=9.9.9 PLATFORMS=linux/amd64 >"$tmp/out" 2>&1; }

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
else
  bad "clean tagged tree: refused:"; cat "$tmp/out" >&2
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
