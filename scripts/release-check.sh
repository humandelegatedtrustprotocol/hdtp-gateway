#!/usr/bin/env bash
# What `make dist` holds a release build to, so the published checksums are ones anyone can
# reproduce from the tag.
#
#   scripts/release-check.sh tree VERSION
#       The working tree is clean as the go command sees it (`git status --porcelain` empty,
#       untracked files included: that is what it stamps as vcs.modified) and HEAD is the commit
#       tag vVERSION names.
#   scripts/release-check.sh binaries VERSION FILE...
#       Every binary's build info (`go version -m`) records vcs.modified=false and vcs.revision
#       equal to the commit vVERSION names. A binary with no VCS stamp is refused.
#
# Run in the checkout being built. scripts/release-check-test.sh holds both to fixtures.
set -euo pipefail

die() { echo "release-check: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: $0 tree VERSION | binaries VERSION FILE..."
mode=$1 version=$2
shift 2
tag=v$version

commit=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") || die "no tag $tag"

case $mode in
tree)
  [ $# -eq 0 ] || die "tree takes no files"
  dirty=$(git status --porcelain)
  [ -z "$dirty" ] || die "the working tree is not clean; a release is built from the tag alone:
$dirty"
  head=$(git rev-parse HEAD)
  [ "$head" = "$commit" ] || die "HEAD is $head, not $tag ($commit)"
  ;;
binaries)
  [ $# -gt 0 ] || die "binaries needs at least one file"
  for f in "$@"; do
    info=$(go version -m "$f") || die "$f: no Go build info"
    printf '%s\n' "$info" | grep -qx "[[:space:]]*build[[:space:]]vcs.modified=false" ||
      die "$f: build info does not record vcs.modified=false (built from a modified tree, or without VCS)"
    printf '%s\n' "$info" | grep -qx "[[:space:]]*build[[:space:]]vcs.revision=$commit" ||
      die "$f: build info does not record vcs.revision=$commit ($tag)"
  done
  ;;
*)
  die "unknown mode $mode"
  ;;
esac
