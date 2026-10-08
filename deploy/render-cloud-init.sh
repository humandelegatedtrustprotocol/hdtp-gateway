#!/usr/bin/env bash
# Renders deploy/cloud-init.yaml for one VM: the two placeholders substituted, the result on
# standard output. The scripts that create a VM from a shell (deploy/gcp, deploy/digitalocean)
# call this; the AWS and Azure templates carry the file themselves and substitute in their own
# language. A placeholder left behind is refused, so a new one added to the file fails here and
# in scripts/deploy-check.mjs rather than reaching a VM as text.
#
#   deploy/render-cloud-init.sh <hostname> <release>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <hostname> <release-tag>" >&2
  exit 2
fi
hostname="$1"
release="$2"
case "$hostname" in
  *[!a-z0-9.-]*|"") echo "render-cloud-init: the hostname is a lower-case DNS name: $hostname" >&2; exit 2 ;;
esac
case "$release" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "render-cloud-init: the release is a tag such as v0.1.1: $release" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
out=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line//'${Hostname}'/$hostname}"
  line="${line//'${Release}'/$release}"
  out+="$line"$'\n'
done < "$here/cloud-init.yaml"

if [[ "$out" == *'${'* ]]; then
  echo "render-cloud-init: a placeholder this script does not know is left in the output" >&2
  exit 1
fi
printf '%s' "$out"
