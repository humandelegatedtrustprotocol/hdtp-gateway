#!/bin/sh
# sibling-guards.sh <root> <repo>: prints, one per line, each comparison the gate of the checkout at
# <root> makes with the sibling repository <repo>, read from the code that makes it: every
# testid.SiblingFile call naming <repo> (as "<file>: <what goes unchecked without it>"), and for
# batondeck the Makefile's dependents. The pre-push hook prints these when
# HDTP_ALLOW_MISSING_SIBLINGS=1 lets a push through without <repo>; TestTheSiblingGuardsListIsTheCode
# holds this list to the SiblingFile calls the Go parser finds.
set -eu
root="$1" repo="$2"
cd "$root"
# The files the Go parser reads (prepush_siblings_test.go siblingCalls): every .go file outside
# node_modules and dot-directories. find prunes by name; grep's --exclude-dir='.?*' also matches the
# `.` it starts from on BSD grep and lists nothing.
find . \( -name node_modules -o -name '.?*' \) -type d -prune -o -type f -name '*.go' \
  -exec grep -Hn -E "testid\.SiblingFile\(t, \"$repo\"," {} + |
  sed -E 's|^\./([^:]*):[0-9]+:.*, "([^"]*)"\)+$|\1: \2|' | sort
if [ "$repo" = batondeck ]; then
  echo "Makefile dependents: the cloud's conformance battery is not compiled or seal-tested against this change"
fi
