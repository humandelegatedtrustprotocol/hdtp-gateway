#!/usr/bin/env bash
# The node builds frp from third_party/frp: upstream github.com/fatedier/frp v0.71.0 with
# third_party/frp.patch applied, and nothing else. go.mod and harness/go.mod both replace the
# module with that directory (a replace does not reach a module that depends on this one, and the
# harness compiles the tunnel and ingress packages through `replace hdtp-gateway => ..`).
#
# Why: v0.71.0 (and frp's master as of 2026-10-07) has three data races in its client, each a field
# read without the lock its writers hold:
#   - client/proxy/proxy_wrapper.go, Wrapper.InWorkConn reads the proxy's phase after releasing
#     pw.mu, while SetRunningStatus writes it: a caller who reaches frps while the client is still
#     recording the proxy as running;
#   - client/service.go, keepControllerWorking reads svr.ctl without ctlMu, while stop sets it to
#     nil: a Stop while that goroutine runs (and a nil dereference if stop wins before its first
#     read);
#   - client/service.go, GracefulClose calls svr.cancel, which Run sets on its own goroutine: a
#     Stop right after Start reads it concurrently, and calls nil if Run has not set it yet (a
#     panic: serve stops the tunnel when the node fails to start).
# TestFRPCallersDuringRegistrationAreServed reproduces the first two under -race, and
# TestFRPStopRightAfterStart the third (both in internal/tunnel).
#
# The copy is every non-test .go file under client/, pkg/, server/ and assets/ (the library; frp's
# cmd/, web/, test/ and doc/ are not compiled by anything here), with frp's go.mod and LICENSE.
#
#   scripts/frp-patch.sh          check: the tree is exactly upstream + the patch, and both go.mod
#                                 files carry the same replace (run by `make check`)
#   scripts/frp-patch.sh --write  rebuild the tree from upstream + the patch
#   scripts/frp-patch.sh --diff   write the patch from the tree as edited (after a change to it)
#
# The upstream module comes from the Go module cache (downloaded once if absent) and is held to
# the h1 hash below, which is the hash go.sum carried for it before the replace.
#
# Remove this, the directory, the patch and both replaces when an frp release carries the fix:
# require that release, `go mod tidy` here and in harness/, and delete what this file names.
set -euo pipefail

MODULE=github.com/fatedier/frp
VERSION=v0.71.0
SUM='h1:hrzMepFp/asl2oAxxLMgffCI/wrzvg6lZyMzxEEnWbQ='
REPLACE="$MODULE $VERSION => "

top="$(cd "$(dirname "$0")/.." && pwd)"
tree="$top/third_party/frp"
patchfile="$top/third_party/frp.patch"
mode="${1:-check}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# upstream, from the module cache, held to its hash
info="$(cd "$work" && GOWORK=off GOFLAGS=-mod=mod go mod download -json "$MODULE@$VERSION")"
dir="$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
sum="$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*"Sum": "\(.*\)",$/\1/p')"
if [ "$sum" != "$SUM" ] || [ -z "$dir" ]; then
  echo "frp-patch: $MODULE@$VERSION hashes to '$sum', want $SUM" >&2
  exit 1
fi

# the copy rule over upstream: base; and the expected tree: base with the patch applied
base="$work/a"
mkdir -p "$base"
cp "$dir/go.mod" "$dir/LICENSE" "$base/"
(cd "$dir" && find client pkg server assets -type f -name '*.go' ! -name '*_test.go') | while IFS= read -r f; do
  mkdir -p "$base/$(dirname "$f")"
  cp "$dir/$f" "$base/$f"
done
chmod -R u+w "$base"

if [ "$mode" = --diff ]; then
  # paths a/ and b/, no timestamps, so the patch is the same bytes wherever it is made
  mkdir -p "$work/d" && cp -R "$base" "$work/d/a" && cp -R "$tree" "$work/d/b"
  (cd "$work/d" && diff -ruN a b || true) | grep -v '^diff -ruN ' |
    sed -e 's|^\(---\) \(a/[^[:space:]]*\).*$|\1 \2|' -e 's|^\(+++\) \(b/[^[:space:]]*\).*$|\1 \2|' >"$patchfile"
  echo "frp-patch: wrote third_party/frp.patch from third_party/frp"
  exit 0
fi

want="$work/frp"
cp -R "$base" "$want"
patch -s -p1 -d "$want" < "$patchfile" || {
  echo "frp-patch: third_party/frp.patch does not apply to $MODULE@$VERSION" >&2
  exit 1
}

case "$mode" in
--write)
  rm -rf "$tree"
  cp -R "$want" "$tree"
  echo "frp-patch: wrote third_party/frp ($MODULE@$VERSION + third_party/frp.patch)"
  ;;
check)
  problems=0
  if ! diff -r "$want" "$tree" >"$work/diff" 2>&1; then
    echo "frp-patch: third_party/frp is not $MODULE@$VERSION + third_party/frp.patch (scripts/frp-patch.sh --write rebuilds it):" >&2
    cat "$work/diff" >&2
    problems=1
  fi
  for m in go.mod harness/go.mod; do
    case "$m" in harness/*) rel=../third_party/frp ;; *) rel=./third_party/frp ;; esac
    if [ "$(grep -c "^replace $REPLACE$rel\$" "$top/$m" || true)" != 1 ]; then
      echo "frp-patch: $m does not carry exactly one 'replace $REPLACE$rel'" >&2
      problems=1
    fi
  done
  # The node's require is the version both replaces name; the harness requires frp only through
  # the node, so a bump here that left the replaces behind would build upstream frp in both.
  if ! grep -q "^[[:space:]]*$MODULE $VERSION\$" "$top/go.mod"; then
    echo "frp-patch: go.mod does not require $MODULE $VERSION, the version the patch is for" >&2
    problems=1
  fi
  [ "$problems" = 0 ] || exit 1
  echo "frp-patch: third_party/frp is $MODULE@$VERSION + third_party/frp.patch; both go.mod files replace it"
  ;;
*)
  echo "usage: scripts/frp-patch.sh [--write|--diff]" >&2
  exit 2
  ;;
esac
