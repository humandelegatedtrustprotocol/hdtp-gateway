#!/usr/bin/env bash
# hdtp-gateway on one DigitalOcean Droplet, from a shell with doctl: an Ubuntu 24.04 Droplet with
# deploy/cloud-init.yaml as its user data, and its address printed with what to do next: point the
# hostname at it (docs/deploy.md). The first boot then builds the node and brings Caddy up for TLS
# on that hostname. Droplets are x86-64; the first boot does not care.
#
# App Platform, the product DigitalOcean's deploy button creates on, is not a host for this node
# (docs/deploy.md says why), so there is no button: this script is the DigitalOcean path.
#
#   HDTP_HOSTNAME=hdtp.example.com HDTP_SSH_KEY=<key id or fingerprint> deploy/digitalocean/deploy.sh
#
# Environment, with its defaults:
#   HDTP_HOSTNAME   required: the name you will point at the Droplet, the node's public URL
#   HDTP_SSH_KEY    required: an SSH key id or fingerprint from `doctl compute ssh-key list`
#   HDTP_RELEASE    v0.1.1              the release tag to build
#   HDTP_REGION     nyc3                the region slug
#   HDTP_SIZE       s-2vcpu-4gb         the size slug (4 GB: the first boot compiles the node)
#   HDTP_IMAGE      ubuntu-24-04-x64    the image slug
#   HDTP_NAME       hdtp-gateway        the Droplet's name
# The Droplet's firewall is DigitalOcean's default, open: 80 and 443 are what a public node needs,
# and SSH is key-only. Add a Cloud Firewall for 22 if you want it closed to the rest of the world.
set -euo pipefail

hostname="${HDTP_HOSTNAME:-}"
sshkey="${HDTP_SSH_KEY:-}"
release="${HDTP_RELEASE:-v0.1.1}"
region="${HDTP_REGION:-nyc3}"
size="${HDTP_SIZE:-s-2vcpu-4gb}"
image="${HDTP_IMAGE:-ubuntu-24-04-x64}"
name="${HDTP_NAME:-hdtp-gateway}"
if [ -z "$hostname" ] || [ -z "$sshkey" ]; then
  echo "deploy/digitalocean/deploy.sh: set HDTP_HOSTNAME and HDTP_SSH_KEY" >&2
  exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"

userdata="$(mktemp)"
trap 'rm -f "$userdata"' EXIT
"$here/../render-cloud-init.sh" "$hostname" "$release" > "$userdata"

ip="$(doctl compute droplet create "$name" \
  --image "$image" --size "$size" --region "$region" \
  --ssh-keys "$sshkey" \
  --user-data-file "$userdata" \
  --wait --format PublicIPv4 --no-header)"
cat <<EOF

hdtp-gateway is building on the Droplet $name ($region), at $ip.

1. Point the hostname at it: an A record, $hostname -> $ip, wherever that name's DNS lives.
   Caddy asks for the certificate on its first start and keeps retrying until the name resolves.
2. Wait for the first boot to finish (minutes: the node and its sidecar are compiled on the Droplet):
       ssh root@$ip cloud-init status --wait
3. Log in with the portal's loopback port tunnelled, and follow the message of the day:
       ssh -L 8080:127.0.0.1:8080 root@$ip
EOF
