#!/bin/sh
# sibling.sh <root> <repo>: prints the checkout of the sibling repository <repo> of the checkout at
# <root>, or nothing when there is none. The places, in order: the variable named for it
# (HDTP_BATONDECK_DIR, HDTP_IDENTITY_DIR, HDTP_SPEC_DIR); <root>/../<repo>, the umbrella's layout and
# a worktree's sibling link; and the directory beside the checkout git keeps <root>'s objects in
# (the umbrella, for `<umbrella>/.git/modules/<name>`; the main checkout's parent, for its `.git`),
# so a worktree anywhere finds the umbrella's. The Makefile's `dependents` reads it; the Go tests
# read internal/testid.SiblingDir, and TestTheTwoSiblingLocatorsAgree holds this to that.
set -eu
root="$1" repo="$2"
case "$repo" in
  batondeck) override="${HDTP_BATONDECK_DIR:-}" ;;
  hdtp-identity) override="${HDTP_IDENTITY_DIR:-}" ;;
  hdtp-spec) override="${HDTP_SPEC_DIR:-}" ;;
  *) echo "sibling.sh: no variable names a $repo checkout" >&2; exit 2 ;;
esac
# A hook in a linked worktree exports GIT_DIR and its siblings: the question is about <root>.
common="$(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_COMMON_DIR -u GIT_INDEX_FILE -u GIT_PREFIX \
  git -C "$root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
by_git=""
case "$common" in
  */.git/modules/*) case "${common##*/.git/modules/}" in */*) ;; *) by_git="${common%/.git/modules/*}/$repo" ;; esac ;;
  */.git) by_git="$(dirname "$(dirname "$common")")/$repo" ;;
esac
for c in "$override" "$(dirname "$root")/$repo" "$by_git"; do
  if [ -n "$c" ] && [ -d "$c" ]; then echo "$c"; exit 0; fi
done
