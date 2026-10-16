#!/bin/sh
# sibling-guards.sh <root> <repo>: prints, one per line, each comparison the gate of the checkout at
# <root> makes with the sibling repository <repo>, read from the code that makes it: every
# testid.SiblingFile call naming <repo> (as "<file>: <what goes unchecked without it>"), and for
# batondeck the Makefile's dependents. The pre-push hook prints these when
# HDTP_ALLOW_MISSING_SIBLINGS=1 lets a push through without <repo>; TestThePrePushHookOnMissingSiblings
# holds this list to the SiblingFile calls the Go parser finds.
set -eu
root="$1" repo="$2"
cd "$root"
grep -rn --include='*.go' --exclude-dir=node_modules -E "testid\.SiblingFile\(t, \"$repo\"," . |
  sed -E 's|^\./([^:]*):[0-9]+:.*, "([^"]*)"\)+$|\1: \2|' | sort
if [ "$repo" = batondeck ]; then
  echo "Makefile dependents: the cloud's conformance battery is not compiled or seal-tested against this change"
fi
