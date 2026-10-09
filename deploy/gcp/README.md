# hdtp-gateway on Google Cloud, from Cloud Shell

This is the walkthrough the **Open in Cloud Shell** button opens beside a clone of the repository.
It runs `deploy/gcp/deploy.sh`: one Arm VM from the Ubuntu 24.04 arm64 image family, a firewall
rule for 80 and 443, and `deploy/cloud-init.yaml` as the VM's first boot, which builds the node
and puts Caddy in front for TLS on your hostname. `docs/deploy.md` says what you get and what it
does not do; the signing steps that make the node yours are the quickstart's.

## 1. Pick the project and the zone

```
gcloud config set project <your project id>
```

T2A (Arm) machine types exist in a subset of regions; `us-central1-a` is the script's default.
Set `HDTP_ZONE` to another zone that has them if you prefer.

## 2. Create the VM

The hostname is the name you will point at the VM, and the node's public URL:

```
HDTP_HOSTNAME=hdtp.example.com deploy/gcp/deploy.sh
```

The script prints the VM's address and the next steps. The A record is yours to write: the script
has no access to your DNS.

## 3. Open the portal

Once `cloud-init status` says `done`, log in with the portal's port tunnelled:

```
gcloud compute ssh hdtp-gateway --zone=us-central1-a -- -L 8080:127.0.0.1:8080
```

The message of the day says how to read the setup link out of the node's log; open it at
`http://localhost:8080` in your own browser. Then continue at `docs/deploy.md`, "After the first
boot".
