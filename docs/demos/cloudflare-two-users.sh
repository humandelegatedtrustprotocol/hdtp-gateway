#!/usr/bin/env bash
# Two users, two real Cloudflare tunnels, one real domain (SPEC §10, edge mode).
#
# Provisions what a test may not: tunnels, DNS records and containers on the
# owner's own Cloudflare zone. `harness/scenario/cloudflare_live_test.go` then
# drives the flow across it. See cloudflare-two-users.md for the walkthrough.
#
# Needs: cloudflared logged in for the zone (or CF_API_TOKEN with DNS:Edit),
# docker, and the hdtp-gateway:harness image (`make harness-image`).
set -euo pipefail

DOMAIN="${HDTP_CF_DOMAIN:?set HDTP_CF_DOMAIN, e.g. example.com}"
ZONE_ID="${CF_ZONE_ID:?set CF_ZONE_ID for $DOMAIN}"
TOKEN="${CF_API_TOKEN:?set CF_API_TOKEN with Zone.DNS:Edit on $DOMAIN}"
IMAGE="${HDTP_IMAGE:-hdtp-gateway:harness}"
WORK="${HDTP_CF_WORK:-$(mktemp -d)}"
mkdir -p "$WORK"   # a named HDTP_CF_WORK may not exist yet; `install` below does not create it
# The wallet. An account is created with no certificate (HDTP §2.0), so a rig whose nodes
# are never taken to a wallet has no identity to pin and the scenario stops at
# "has no certificate yet". `hdtp` is the wallet here, the way a person's is.
WALLET="${HDTP_WALLET:-../hdtp-identity/target/release/pact}"
# A public resolver, on purpose: Docker Desktop forwards the host's resolver into
# containers, so one NXDOMAIN cached before the record existed makes the name
# unresolvable for the whole negative TTL — long after the record is live.
RESOLVER="${HDTP_CF_RESOLVER:-1.1.1.1}"

if [ "${1:-}" = "--down" ]; then
  docker rm -f hdtpcf-alice hdtpcf-bob hdtpcf-alice-cfd hdtpcf-bob-cfd \
    hdtpcf-alice-bridge hdtpcf-bob-bridge hdtpcf-alice-limitd hdtpcf-bob-limitd >/dev/null 2>&1 || true
  docker network rm hdtpcf >/dev/null 2>&1 || true
  if [ "${2:-}" = "--wipe" ]; then
    docker volume rm hdtpcf-alice-data hdtpcf-bob-data >/dev/null 2>&1 || true
    echo "containers and their DATA removed"
  else
    echo "containers removed; their data volumes are kept (add --wipe to drop them)"
  fi
  echo "tunnels and DNS records are still yours to delete"
  exit 0
fi

docker network create hdtpcf >/dev/null 2>&1 || true
i=0
for who in alice bob; do
  port=$((18120 + i)); i=$((i + 1))

  cloudflared tunnel create "hdtp-$who" >/dev/null 2>&1 || true
  id=$(cloudflared tunnel list --output json | python3 -c "
import sys,json
print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='hdtp-$who'))")

  # cloudflared's own DNS routing only works for the zone its cert was issued
  # for, and silently APPENDS that zone otherwise — creating
  # '$who.$DOMAIN.<its-zone>'. The API is explicit about which zone it writes to.
  curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
    --data "{\"type\":\"CNAME\",\"name\":\"$who\",\"content\":\"$id.cfargotunnel.com\",\"proxied\":true}" \
    >/dev/null 2>&1 || echo "  ($who record exists already)"

  # install, not cp: the source is mode 0400 and a re-run must overwrite it.
  install -m 0600 ~/.cloudflared/"$id".json "$WORK/creds-$who.json"
  cat > "$WORK/config-$who.yml" <<EOF
tunnel: $id
credentials-file: /etc/cloudflared/creds.json
ingress:
  - hostname: $who.$DOMAIN
    service: https://localhost:8443
    originRequest:
      # The node serves its OWN certificate; Cloudflare is the public TLS. That
      # is what edge mode means, and why identity comes from sealed envelopes.
      noTLSVerify: true
  - service: http_status:404
EOF

  docker rm -f "hdtpcf-$who" "hdtpcf-$who-cfd" "hdtpcf-$who-bridge" "hdtpcf-$who-limitd" >/dev/null 2>&1 || true
  # A NAMED VOLUME, so a restart keeps the node's identity. Without one every
  # `docker run` starts an empty /data: accounts, passkeys and contacts are all
  # gone, the zero-passkey rule reopens the setup wizard, and it looks like
  # clearing cookies logged you out. State belongs outside the container.
  docker volume create "hdtpcf-$who-data" >/dev/null 2>&1 || true
  docker run -d --name "hdtpcf-$who" --network hdtpcf --dns "$RESOLVER" \
    -v "hdtpcf-$who-data":/data \
    -p "127.0.0.1:$port:8081" \
    -e HDTP_PUBLIC_BIND=0.0.0.0:8443 \
    -e HDTP_INTERNAL_BIND=127.0.0.1:8080 \
    -e "HDTP_PUBLIC_URL=https://$who.$DOMAIN" \
    -e HDTP_TUNNEL=cloudflare \
    -e "HDTP_TUNNEL_HOSTNAME=$who.$DOMAIN" \
    -e HDTP_TUNNEL_SIDECAR=true \
    -e "HDTP_TUNNEL_TOKEN=$(cloudflared tunnel token "hdtp-$who")" \
    "$IMAGE" serve >/dev/null

  # The node's limits sidecar (SPEC §5.7): the same image as /hdtp-limitd, sharing /data, where
  # its socket is. Until it answers, the node refuses every sealed call.
  docker run -d --name "hdtpcf-$who-limitd" --network none -v "hdtpcf-$who-data":/data \
    --entrypoint /hdtp-limitd "$IMAGE" -config /etc/hdtp-limitd/limits.json >/dev/null

  # The connector shares the NODE's network namespace, so it delivers over
  # loopback. A connector in its own container arrives from an RFC 1918 address
  # and edge mode's LAN guard refuses it (SPEC §12.2) — that deployment has to
  # turn lan_connections on.
  # The portal binds the container's LOOPBACK (SPEC §8.3 refuses a non-loopback
  # internal bind without auth and TLS), so publishing a port reaches nothing on
  # its own. This sidecar shares the node's namespace and forwards the published
  # port to that loopback — the node's own guard stays exactly as it was.
  docker run -d --name "hdtpcf-$who-bridge" --network "container:hdtpcf-$who" \
    alpine/socat TCP-LISTEN:8081,fork,reuseaddr TCP:127.0.0.1:8080 >/dev/null

  docker run -d --name "hdtpcf-$who-cfd" --network "container:hdtpcf-$who" \
    -v "$WORK/config-$who.yml":/etc/cloudflared/config.yml:ro \
    -v "$WORK/creds-$who.json":/etc/cloudflared/creds.json:ro \
    cloudflare/cloudflared:latest \
    --config /etc/cloudflared/config.yml --no-autoupdate tunnel run >/dev/null
done

sleep 12
for who in alice bob; do
  name="$(printf '%s' "${who:0:1}" | tr a-z A-Z)${who:1}"
  docker exec "hdtpcf-$who" /hdtp-gateway account create \
    --slug "$who" --name "$name" >/dev/null 2>&1 \
    || true  # already there on a re-run against a kept volume

  # THE WALLET STEP, and the rig is not a 2.0 rig without it. An account holds a key and
  # no certificate; the person's root is what makes it an identity, and it lives in a
  # vault this script owns because the two users here are fictional. A real owner does
  # these three commands themselves, which is the point of the separation.
  # `account certificate` prints "<slug>: root sha256:..." when there is one, and
  # "<slug> has no leaf yet" when there is not. Matching the ROOT line is what makes a
  # re-run against a kept volume a no-op; matching "^root" matched neither, so every
  # re-run minted a fresh leaf for an identity that already had one.
  if ! docker exec "hdtpcf-$who" /hdtp-gateway account certificate -slug "$who" 2>/dev/null | grep -q "^$who: root sha256:"; then
    if [ ! -x "$WALLET" ]; then
      echo "  ($who has no certificate and no wallet at $WALLET: build it with 'cargo build --release -p pact' in hdtp-identity, or set HDTP_WALLET)"
    else
      if [ ! -e "$WORK/$who.vault" ]; then
        printf 'rig-%s-passphrase' "$who" > "$WORK/$who.pass"
        chmod 600 "$WORK/$who.pass"   # the wallet refuses a passphrase file others can read
        PACT_PASSPHRASE_FILE="$WORK/$who.pass" "$WALLET" id create --name "$name" --vault "$WORK/$who.vault" >/dev/null
      fi
      docker exec "hdtpcf-$who" /hdtp-gateway account csr -slug "$who" > "$WORK/$who.csr"
      PACT_PASSPHRASE_FILE="$WORK/$who.pass" "$WALLET" id issue --vault "$WORK/$who.vault" \
        --csr "$WORK/$who.csr" --yes --chain-out "$WORK/$who.chain.pem" >/dev/null
      docker cp "$WORK/$who.chain.pem" "hdtpcf-$who:/tmp/chain.pem" >/dev/null
      docker exec "hdtpcf-$who" /hdtp-gateway account install-leaf -slug "$who" -chain /tmp/chain.pem
    fi
  fi

  n=$(docker logs "hdtpcf-$who-cfd" 2>&1 | grep -c "Registered tunnel connection" || true)
  port=$([ "$who" = alice ] && echo 18120 || echo 18121)
  echo "hdtpcf-$who: $n edge connections | public https://$who.$DOMAIN | portal http://localhost:$port/"
done
echo
echo "now: HDTP_HARNESS_LIVE=1 HDTP_CF_DOMAIN=$DOMAIN go test ./scenario/ -run TestTwoUsersOverRealCloudflare -v"
echo "then, black-box: hdtp vectors intrude --against https://alice.$DOMAIN/a/alice/mcp --card <alice's card>"
echo "  (the node serves no card at a URL of its own - SPEC sec. 9 puts it on the invite landing page)"
