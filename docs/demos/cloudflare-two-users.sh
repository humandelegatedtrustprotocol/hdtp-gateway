#!/usr/bin/env bash
# Two users, two real Cloudflare tunnels, one real domain (SPEC §10, edge mode).
#
# Provisions what a test may not: tunnels, DNS records and containers on the
# owner's own Cloudflare zone. `harness/scenario/cloudflare_live_test.go` then
# drives the flow across it. See cloudflare-two-users.md for the walkthrough.
#
# Needs: cloudflared logged in for the zone (or CF_API_TOKEN with DNS:Edit),
# docker, and the pact-gateway:harness image (`make harness-image`).
set -euo pipefail

DOMAIN="${PACT_CF_DOMAIN:?set PACT_CF_DOMAIN, e.g. example.com}"
ZONE_ID="${CF_ZONE_ID:?set CF_ZONE_ID for $DOMAIN}"
TOKEN="${CF_API_TOKEN:?set CF_API_TOKEN with Zone.DNS:Edit on $DOMAIN}"
IMAGE="${PACT_IMAGE:-pact-gateway:harness}"
WORK="${PACT_CF_WORK:-$(mktemp -d)}"
mkdir -p "$WORK"   # a named PACT_CF_WORK may not exist yet; `install` below does not create it
# The wallet. An account is created with no certificate (PACT 2.0), so a rig whose nodes
# are never taken to a wallet has no identity to pin and the scenario stops at
# "has no certificate yet". `pact` is the wallet here, the way a person's is.
WALLET="${PACT_WALLET:-../pact-identity/target/release/pact}"
# A public resolver, on purpose: Docker Desktop forwards the host's resolver into
# containers, so one NXDOMAIN cached before the record existed makes the name
# unresolvable for the whole negative TTL — long after the record is live.
RESOLVER="${PACT_CF_RESOLVER:-1.1.1.1}"

if [ "${1:-}" = "--down" ]; then
  docker rm -f pactcf-alice pactcf-bob pactcf-alice-cfd pactcf-bob-cfd \
    pactcf-alice-bridge pactcf-bob-bridge >/dev/null 2>&1 || true
  docker network rm pactcf >/dev/null 2>&1 || true
  if [ "${2:-}" = "--wipe" ]; then
    docker volume rm pactcf-alice-data pactcf-bob-data >/dev/null 2>&1 || true
    echo "containers and their DATA removed"
  else
    echo "containers removed; their data volumes are kept (add --wipe to drop them)"
  fi
  echo "tunnels and DNS records are still yours to delete"
  exit 0
fi

docker network create pactcf >/dev/null 2>&1 || true
i=0
for who in alice bob; do
  port=$((18120 + i)); i=$((i + 1))

  cloudflared tunnel create "pact-$who" >/dev/null 2>&1 || true
  id=$(cloudflared tunnel list --output json | python3 -c "
import sys,json
print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='pact-$who'))")

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

  docker rm -f "pactcf-$who" "pactcf-$who-cfd" "pactcf-$who-bridge" >/dev/null 2>&1 || true
  # A NAMED VOLUME, so a restart keeps the node's identity. Without one every
  # `docker run` starts an empty /data: accounts, passkeys and contacts are all
  # gone, the zero-passkey rule reopens the setup wizard, and it looks like
  # clearing cookies logged you out. State belongs outside the container.
  docker volume create "pactcf-$who-data" >/dev/null 2>&1 || true
  docker run -d --name "pactcf-$who" --network pactcf --dns "$RESOLVER" \
    -v "pactcf-$who-data":/data \
    -p "127.0.0.1:$port:8081" \
    -e PACT_PUBLIC_BIND=0.0.0.0:8443 \
    -e PACT_INTERNAL_BIND=127.0.0.1:8080 \
    -e "PACT_PUBLIC_URL=https://$who.$DOMAIN" \
    -e PACT_TUNNEL=cloudflare \
    -e "PACT_TUNNEL_HOSTNAME=$who.$DOMAIN" \
    -e PACT_TUNNEL_SIDECAR=true \
    -e "PACT_TUNNEL_TOKEN=$(cloudflared tunnel token "pact-$who")" \
    "$IMAGE" serve >/dev/null

  # The connector shares the NODE's network namespace, so it delivers over
  # loopback. A connector in its own container arrives from an RFC 1918 address
  # and edge mode's LAN guard refuses it (SPEC §12.2) — that deployment has to
  # turn lan_connections on.
  # The portal binds the container's LOOPBACK (SPEC §8.3 refuses a non-loopback
  # internal bind without auth and TLS), so publishing a port reaches nothing on
  # its own. This sidecar shares the node's namespace and forwards the published
  # port to that loopback — the node's own guard stays exactly as it was.
  docker run -d --name "pactcf-$who-bridge" --network "container:pactcf-$who" \
    alpine/socat TCP-LISTEN:8081,fork,reuseaddr TCP:127.0.0.1:8080 >/dev/null

  docker run -d --name "pactcf-$who-cfd" --network "container:pactcf-$who" \
    -v "$WORK/config-$who.yml":/etc/cloudflared/config.yml:ro \
    -v "$WORK/creds-$who.json":/etc/cloudflared/creds.json:ro \
    cloudflare/cloudflared:latest \
    --config /etc/cloudflared/config.yml --no-autoupdate tunnel run >/dev/null
done

sleep 12
for who in alice bob; do
  name="$(printf '%s' "${who:0:1}" | tr a-z A-Z)${who:1}"
  docker exec "pactcf-$who" /pact-gateway account create \
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
  if ! docker exec "pactcf-$who" /pact-gateway account certificate -slug "$who" 2>/dev/null | grep -q "^$who: root sha256:"; then
    if [ ! -x "$WALLET" ]; then
      echo "  ($who has no certificate and no wallet at $WALLET: build it with 'cargo build --release -p pact' in pact-identity, or set PACT_WALLET)"
    else
      if [ ! -e "$WORK/$who.vault" ]; then
        printf 'rig-%s-passphrase' "$who" > "$WORK/$who.pass"
        chmod 600 "$WORK/$who.pass"   # the wallet refuses a passphrase file others can read
        PACT_PASSPHRASE_FILE="$WORK/$who.pass" "$WALLET" id create --name "$name" --vault "$WORK/$who.vault" >/dev/null
      fi
      docker exec "pactcf-$who" /pact-gateway account csr -slug "$who" > "$WORK/$who.csr"
      PACT_PASSPHRASE_FILE="$WORK/$who.pass" "$WALLET" id issue --vault "$WORK/$who.vault" \
        --csr "$WORK/$who.csr" --yes --chain-out "$WORK/$who.chain.pem" >/dev/null
      docker cp "$WORK/$who.chain.pem" "pactcf-$who:/tmp/chain.pem" >/dev/null
      docker exec "pactcf-$who" /pact-gateway account install-leaf -slug "$who" -chain /tmp/chain.pem
    fi
  fi

  n=$(docker logs "pactcf-$who-cfd" 2>&1 | grep -c "Registered tunnel connection" || true)
  port=$([ "$who" = alice ] && echo 18120 || echo 18121)
  echo "pactcf-$who: $n edge connections | public https://$who.$DOMAIN | portal http://localhost:$port/"
done
echo
echo "now: PACT_HARNESS_LIVE=1 PACT_CF_DOMAIN=$DOMAIN go test ./scenario/ -run TestTwoUsersOverRealCloudflare -v"
echo "then, black-box: pact vectors intrude --against https://alice.$DOMAIN/a/alice/mcp --card <alice's card>"
echo "  (the node serves no card at a URL of its own - SPEC sec. 9 puts it on the invite landing page)"
