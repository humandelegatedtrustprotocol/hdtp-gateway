#!/usr/bin/env bash
# The node builds frp from third_party/frp: upstream github.com/fatedier/frp v0.71.0 with
# third_party/frp.patch applied, and nothing else. go.mod and harness/go.mod both replace the
# module with that directory (a replace does not reach a module that depends on this one, and the
# harness compiles the tunnel and ingress packages through `replace hdtp-gateway => ..`).
#
# Why: v0.71.0 (and frp's master as of 2026-10-07) has these data races, each a field read without
# the lock its writers hold, or written on a goroutine the reader has no order with:
#   - client/proxy/proxy_wrapper.go, Wrapper.InWorkConn reads the proxy's phase after releasing
#     pw.mu, while SetRunningStatus writes it: a caller who reaches frps while the client is still
#     recording the proxy as running;
#   - client/service.go, keepControllerWorking reads svr.ctl without ctlMu, while stop sets it to
#     nil: a Stop while that goroutine runs (and a nil dereference if stop wins before its first
#     read);
#   - client/service.go, GracefulClose calls svr.cancel, which Run sets on its own goroutine: a
#     Stop right after Start reads it concurrently, and calls nil if Run has not set it yet (a
#     panic: serve stops the tunnel when the node fails to start);
#   - server/service.go, the same between frps' Close and Run: the ingress data plane stopped
#     right after it started.
# Under -race, TestFRPCallersDuringRegistrationAreServed reproduces the first two,
# TestFRPStopRightAfterStart the third (internal/tunnel), TestDataPlaneStopRightAfterStart the
# fourth (internal/ingress).
#
# The copy is every non-test .go file under client/, pkg/, server/ and assets/ (the library; frp's
# cmd/, web/, test/ and doc/ are not compiled by anything here), with frp's go.mod and LICENSE.
#
#   scripts/frp-patch.sh          check: the tree is exactly upstream + the patch, and both go.mod
#                                 files carry the same replace (run by `make check`)
#   scripts/frp-patch.sh --write  rebuild the tree from upstream + the patch
#   scripts/frp-patch.sh --diff   write the patch from the tree as edited (after a change to it)
#   scripts/frp-patch.sh --vulncheck <govulncheck command>
#                                 the node's govulncheck sees frp only as ./third_party/frp, with
#                                 no version to match advisories against; this scans upstream
#                                 frp v0.71.0 in a module of its own and fails on any advisory for
#                                 frp itself (run by `make vulncheck`)
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

if [ "$mode" = --vulncheck ]; then
  shift
  [ "$#" -gt 0 ] || { echo "usage: scripts/frp-patch.sh --vulncheck <govulncheck command>" >&2; exit 2; }
  v="$work/v"
  mkdir -p "$v"
  printf 'package main\n\nimport (\n\t_ "%s/client"\n\t_ "%s/server"\n)\n\nfunc main() {}\n' "$MODULE" "$MODULE" >"$v/main.go"
  (cd "$v" && export GOWORK=off GOFLAGS=-mod=mod &&
    go mod init frpvulncheck >/dev/null 2>&1 &&
    go mod edit -require="$MODULE@$VERSION" && go mod tidy >/dev/null 2>&1 &&
    "$@" -scan module -json >"$work/vuln.json") || {
    echo "frp-patch: govulncheck did not run over $MODULE@$VERSION" >&2
    exit 1
  }
  # The scan must have seen frp at this version (a scan that saw nothing finds nothing), and no
  # finding may be in frp itself; frp's dependencies are the node's own scan's, at the node's
  # versions.
  node -e '
    const [file, mod, ver] = process.argv.slice(1)
    const text = require("fs").readFileSync(file, "utf8")
    const objs = []
    for (let i = 0, depth = 0, start = 0, str = false, esc = false; i < text.length; i++) {
      const c = text[i]
      if (str) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === "\"") str = false; continue }
      if (c === "\"") str = true
      else if (c === "{") { if (depth++ === 0) start = i }
      else if (c === "}" && --depth === 0) objs.push(JSON.parse(text.slice(start, i + 1)))
    }
    const seen = objs.some(o => o.SBOM && (o.SBOM.modules || []).some(m => m.path === mod && m.version === ver))
    if (!seen) { console.error(`frp-patch: govulncheck did not scan ${mod}@${ver}`); process.exit(1) }
    const hits = [...new Set(objs.filter(o => o.finding && (o.finding.trace || [])[0]?.module === mod).map(o => o.finding.osv))]
    if (hits.length) { console.error(`frp-patch: ${mod}@${ver} is affected by ${hits.join(", ")}: the patched copy carries it too`); process.exit(1) }
    console.log(`frp-patch: govulncheck scanned ${mod}@${ver}: no advisory for it`)
  ' "$work/vuln.json" "$MODULE" "$VERSION"
  exit
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
  echo "usage: scripts/frp-patch.sh [--write|--diff|--vulncheck <govulncheck command>]" >&2
  exit 2
  ;;
esac
