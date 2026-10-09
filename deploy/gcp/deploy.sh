#!/usr/bin/env bash
# hdtp-gateway on one Arm VM in Google Cloud, from a shell with gcloud (Cloud Shell, or your own):
# a firewall rule for 80 and 443, a Compute Engine instance from the Ubuntu 24.04 arm64 image
# family with deploy/cloud-init.yaml as its user-data, and the instance's address printed with
# what to do next: point the hostname at it (docs/deploy.md). The first boot then builds the node
# and brings Caddy up for TLS on that hostname.
#
#   HDTP_HOSTNAME=hdtp.example.com deploy/gcp/deploy.sh
#
# Environment, with its defaults:
#   HDTP_HOSTNAME   required: the name you will point at the VM, the node's public URL
#   HDTP_RELEASE    v0.1.2              the release tag to build
#   HDTP_ZONE       us-central1-a       a zone that offers T2A (Arm) machine types
#   HDTP_MACHINE    t2a-standard-2      an Arm machine type (2 vCPUs, 8 GB)
#   HDTP_NAME       hdtp-gateway        the instance's name
# The project is gcloud's current one (`gcloud config set project <id>`).
set -euo pipefail

hostname="${HDTP_HOSTNAME:-}"
release="${HDTP_RELEASE:-v0.1.2}"
zone="${HDTP_ZONE:-us-central1-a}"
machine="${HDTP_MACHINE:-t2a-standard-2}"
name="${HDTP_NAME:-hdtp-gateway}"
if [ -z "$hostname" ]; then
  echo "deploy/gcp/deploy.sh: set HDTP_HOSTNAME to the name you will point at the VM" >&2
  exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"

userdata="$(mktemp)"
trap 'rm -f "$userdata"' EXIT
"$here/../render-cloud-init.sh" "$hostname" "$release" > "$userdata"

if ! gcloud compute firewall-rules describe hdtp-gateway-web >/dev/null 2>&1; then
  gcloud compute firewall-rules create hdtp-gateway-web \
    --direction=INGRESS --action=ALLOW --rules=tcp:80,tcp:443,udp:443 \
    --source-ranges=0.0.0.0/0 --target-tags=hdtp-gateway
fi

gcloud compute instances create "$name" \
  --zone="$zone" \
  --machine-type="$machine" \
  --image-family=ubuntu-2404-lts-arm64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --tags=hdtp-gateway \
  --metadata-from-file=user-data="$userdata"

ip="$(gcloud compute instances describe "$name" --zone="$zone" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
cat <<EOF

hdtp-gateway is building on $name ($zone), at $ip.

1. Point the hostname at it: an A record, $hostname -> $ip, wherever that name's DNS lives.
   Caddy asks for the certificate on its first start and keeps retrying until the name resolves.
2. Wait for the first boot to finish (minutes: the node and its sidecar are compiled on the VM):
       gcloud compute ssh $name --zone=$zone -- cloud-init status --wait
3. Log in with the portal's loopback port tunnelled, and follow the message of the day:
       gcloud compute ssh $name --zone=$zone -- -L 8080:127.0.0.1:8080

Port 22 is as your network's firewall rules have it (the default network's default-allow-ssh opens
it to everyone); login is by key only, through gcloud.
EOF
