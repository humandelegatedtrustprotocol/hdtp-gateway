# Deploying a node to a cloud

One VM, with TLS on a hostname, from a template: what each provider's path creates, what you get as
the public host, and what is not offered and why. Every path ends at the same place as the
[quickstart](quickstart.md): a setup link in the node's log, a passkey, and the signing steps that
make the node yours. Those steps are the quickstart's and are not repeated here.

| Provider | Path | Public host | Status | Last run |
|---|---|---|---|---|
| AWS | `deploy/aws/hdtp-gateway.cfn.json`, a CloudFormation template | a name in your Route 53 zone | Template validated offline by `make deploy-check` on 2026-10-09; not yet run on AWS by the maintainers | |
| Azure | `deploy/azure/azuredeploy.json`, a Deploy to Azure button | `<label>.<region>.cloudapp.azure.com` | Template validated offline by `make deploy-check` on 2026-10-09; not yet run on Azure by the maintainers | |
| Google Cloud | `deploy/gcp/deploy.sh`, an Open in Cloud Shell button | a name you point at the VM | Script validated offline by `make deploy-check` on 2026-10-09; not yet run on Google Cloud by the maintainers | |
| DigitalOcean | `deploy/digitalocean/deploy.sh`, a Droplet | a name you point at the Droplet | Script validated offline by `make deploy-check` on 2026-10-09; not yet run on DigitalOcean by the maintainers | |
| Fly.io | no template: [why](#flyio-render-and-digitaloceans-app-platform) | | no template | |
| Render | no template: [why](#flyio-render-and-digitaloceans-app-platform) | | no template | |
| Cloudflare | the Tunnel, on any machine: [below](#cloudflare) | a name on your zone | Two nodes over two real tunnels, last run 2026-09-18 ([the demo](demos/cloudflare-two-users.md)) | 2026-09-18 |

"Validated offline" means exactly this: `make deploy-check` (`scripts/deploy-check.mjs`, in
`make check`) parses every template, holds the shared first boot to `compose.yaml` and to the
node's configuration names, holds each template's copy of it to the file, holds every port, address
and header to the code that reads it, and holds this document to the files and `make` targets it
names. Nothing here has created a VM on a provider; the "Last run" column is empty until someone
does, and the date goes there.

## What every VM path does

The four VM paths share one first boot, `deploy/cloud-init.yaml` (a cloud-config; AWS and Azure
carry it inside their templates, Google Cloud and DigitalOcean render it with
`deploy/render-cloud-init.sh`). On an Ubuntu 24.04 VM it:

1. installs Docker from Docker's own apt repository, as [its
   documentation](https://docs.docker.com/engine/install/ubuntu/) writes it, with `docker-ce` held to
   major 29 — the version the quickstart measured — by an apt preference;
2. makes a service user, `hdtp`, in the `docker` group, owning `/opt/hdtp`;
3. fetches this repository at one release tag into `/opt/hdtp` (the tag is a parameter; the
   templates default to `v0.1.1`);
4. vendors the limits sidecar's crates as `make limitd-vendor` does, in the Rust image the
   `Dockerfile` builds the sidecar with, since the VM has no cargo;
5. runs the shipped `compose.yaml` with an override beside it: the node told its public URL
   (`HDTP_PUBLIC_URL=https://<hostname>`, so the Settings page shows it locked and `account csr`
   knows the address), and **Caddy** published on 80, 443 and 443/udp with a certificate for the hostname
   from its automatic HTTPS (Let's Encrypt or ZeroSSL), each request carried to the node's
   listener over TLS. The compose build compiles the node (Go) and the sidecar (Rust) on the VM:
   minutes, and not measured on any instance size, which is why the defaults have 4 GiB of memory or
   more rather than 2;
6. writes a login message: where the setup link is and how to open it.

What the node gets from this, read from the code and not from the provider:

- **The posture is `deploy/envoy`'s minus two things.** Caddy, like Envoy, ends the caller's TLS
  and writes the caller's address into `X-HDTP-Client-Address`, which the node reads from Caddy's
  address alone (`HDTP_PROXY_ADDRESS`; `internal/public/listener.go`). Unlike Envoy, Caddy cannot
  forward a caller's certificate chain, so a caller proves nothing on the transport and its sealed
  envelope is its proof — as behind any terminating edge (SPEC §10.1). And Caddy limits nothing
  per address before the node: layer 1 of the node's rate limits is Envoy's configuration
  (`deploy/envoy/envoy.yaml`); behind Caddy only the limits sidecar's per-caller budgets apply
  (`docs/operations.md`, "Call budgets"). An operator who wants layer 1 runs `deploy/envoy` with a
  certificate instead.
- **The portal stays on the VM's loopback**, as in `compose.yaml`: Caddy proxies the node's public
  listener only. You reach the portal through an SSH tunnel and sign in at `http://localhost:8080`,
  which is the name your passkey is bound to.
- **`doctor`'s probe says `wrong_cert` once a leaf is installed.** In direct mode `doctor` probes
  the public URL expecting the node's own chain (`internal/cli/doctor.go`,
  `internal/tunnel/probe.go`); through Caddy it meets the WebPKI certificate and reports
  `wrong_cert`, as it does behind `deploy/envoy`. A peer accepts that certificate: the outbound
  client takes the pinned chain or WebPKI validity for the hostname (`internal/outbound/client.go`).
  Every other `doctor` line applies.
- **The data is the VM's disk.** SQLite in the `hdtp-data` volume, Caddy's certificates in
  `caddy-data`. Nothing leaves the VM; nothing backs it up but you (`docs/operations.md`).

What was measured, on this machine rather than on a provider (Docker 29.8.2, Compose v5.5.1,
2026-10-09): the shipped `compose.yaml` with the override and the Caddyfile this file writes, the
hostname resolved to loopback and Caddy's internal CA standing in for ACME. The node started with
`public: https://<hostname>` and `mode=direct`; an identity was created, its request signed by the
`hdtp` CLI and the chain installed; through Caddy, with the hostname as the server name, the
reachability probe answered `200` with its nonce and the instance's URL, and `tools/list` on
`/a/<slug>/mcp` answered the guest tier's tools; `doctor` then reported the leaf, the sidecar
answering and the probe `wrong_cert`, as the bullet above says. Not measured: a provider's VM,
the first boot's package and build steps, and a certificate from a public CA.

The node's sources and `compose.yaml` on the VM are the release tag's; the override and the
Caddyfile are this file's, at the commit you deployed from. `docker compose` in `/opt/hdtp` reads
both files and `.env` by itself.

## AWS

`deploy/aws/hdtp-gateway.cfn.json` creates, in one stack and in the region's default VPC (a
region without one refuses the stack): a security group (80 and 443 to everyone, 22 to the CIDR
you give), one Arm EC2 instance from Canonical's current Ubuntu 24.04 arm64 AMI (resolved from
their public SSM parameter), an Elastic IP, and an A record for your hostname in the Route 53
hosted zone you name. The first boot is the cloud-init above, embedded
line by line. Parameters: `Hostname`, `HostedZoneId`, `SshCidr` (required), `InstanceType`
(`t4g.medium`), `KeyName` (the template allows it empty, but it is required in practice: the setup
link is only in the node's log, and without a key pair nothing can log in to read it; an SSM
session would need an instance role, which this template does not create), `Release`, `Ami` (leave
it). Outputs: the URL, the address, and the SSH command with the portal's port tunnelled.

There is no Launch Stack button. CloudFormation's quick-create links take the template from an
Amazon S3 URL and no other (per [AWS's
documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html)
as of 2026-10), and this repository publishes no bucket. Launch it from a clone instead:

```
aws cloudformation deploy --stack-name hdtp-gateway \
  --template-file deploy/aws/hdtp-gateway.cfn.json \
  --parameter-overrides Hostname=hdtp.example.com HostedZoneId=Z0123456789ABCDEFGHIJ \
      SshCidr=203.0.113.4/32 KeyName=my-key
aws cloudformation describe-stacks --stack-name hdtp-gateway --query 'Stacks[0].Outputs'
```

or, in the console, **Create stack → Upload a template file** with that file. Then continue at
[After the first boot](#after-the-first-boot); the user is `ubuntu`.

## Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhumandelegatedtrustprotocol%2Fhdtp-gateway%2Fmain%2Fdeploy%2Fazure%2Fazuredeploy.json)

The button is the form [Azure
documents](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-to-azure-button):
the portal's template page with the URL-encoded raw URL of `deploy/azure/azuredeploy.json` at
`main`. It creates, in a resource group you pick: a Standard static public IP with a DNS label, a
network security group (80 and 443 to everyone, 22 to the prefix you give), a virtual network, a
network interface, and one Arm VM (`Canonical:ubuntu-24_04-lts:server-arm64:latest`,
`Standard_D2ps_v5` by default) with the cloud-init as its custom data and your SSH public key as
its only login. The hostname is the public IP's own name, `<label>.<region>.cloudapp.azure.com`,
nothing to point anywhere — or a name of your own in the `hostname` parameter, pointed at the
`publicIp` output. Prefer your own: `cloudapp.azure.com` is not on the [Public Suffix
List](https://publicsuffix.org/list/) (checked 2026-10-09; `cloudapp.net` is), so Let's Encrypt
counts every name under it against `azure.com`'s limit of 50 certificates per 7 days ([its rate
limits](https://letsencrypt.org/docs/rate-limits/)); Caddy's automatic HTTPS also tries ZeroSSL, and
whether either issues for such a name was not measured. Parameters: `dnsLabel`, `sshPublicKey`,
`sshSourceAddressPrefix` (required), `hostname` (empty), `adminUsername` (`azureuser`), `vmSize`,
`release`, `location`. `deploy/azure/azuredeploy.parameters.json` is a sample for the CLI:

```
az group create --name hdtp-gateway --location westeurope
az deployment group create --resource-group hdtp-gateway \
  --template-file deploy/azure/azuredeploy.json \
  --parameters deploy/azure/azuredeploy.parameters.json \
  --parameters dnsLabel=my-node sshPublicKey="$(cat ~/.ssh/id_ed25519.pub)" sshSourceAddressPrefix=203.0.113.4/32
```

The deployment's outputs give the hostname, the URL and the SSH command. Then continue at
[After the first boot](#after-the-first-boot).

## Google Cloud

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/humandelegatedtrustprotocol/hdtp-gateway&cloudshell_git_branch=main&cloudshell_tutorial=deploy/gcp/README.md)

The button is the form [Google
documents](https://docs.cloud.google.com/shell/docs/open-in-cloud-shell): Cloud Shell with this
repository cloned at `main` and `deploy/gcp/README.md` open as the walkthrough. It runs
`deploy/gcp/deploy.sh` in your current project: a firewall rule for 80 and 443, and one Arm VM
(`t2a-standard-2`, the `ubuntu-2404-lts-arm64` image family, `us-central1-a` by default; T2A
exists in a subset of zones) with the rendered cloud-init as its `user-data`. The script prints the
VM's address: the A record for your hostname is yours to write, and Caddy keeps asking for its
certificate until the name resolves. The same script runs anywhere `gcloud` does:

```
HDTP_HOSTNAME=hdtp.example.com deploy/gcp/deploy.sh
```

Then continue at [After the first boot](#after-the-first-boot); SSH is `gcloud compute ssh`.

## DigitalOcean

`deploy/digitalocean/deploy.sh` creates one Droplet (`ubuntu-24-04-x64`, `s-2vcpu-4gb`, `nyc3`
by default; Droplets are x86-64, which the first boot does not mind) with the rendered cloud-init as
its user data, waits for it, and prints its address: the A record for your hostname is yours to
write. The Droplet's firewall is DigitalOcean's default, open; 80 and 443 are what a public node
needs, and SSH is key-only.

```
HDTP_HOSTNAME=hdtp.example.com HDTP_SSH_KEY=<id from doctl compute ssh-key list> deploy/digitalocean/deploy.sh
```

Then continue at [After the first boot](#after-the-first-boot); the user is `root`. The image slug
is per DigitalOcean's image list as of 2026-10 and was not checked by a run. There is no Deploy to
DigitalOcean button: that button creates an App Platform app, which cannot host this node
([below](#flyio-render-and-digitaloceans-app-platform)).

## Fly.io, Render, and DigitalOcean's App Platform

No template is offered for these, for reasons in the node rather than in the providers:

- **The limits sidecar shares a unix socket with the node** (`compose.yaml`; SPEC §5.7), and until
  it answers the node refuses every sealed call. The shipped image is distroless and runs the node
  alone, and this repository builds no image that runs the node and the sidecar together; each of
  these providers builds one image from the Dockerfile you name, so hosting the node there needs
  such an image first.
- **The node's public listener speaks only TLS** (`internal/public/listener.go`), and Render's
  load balancer "terminates SSL for inbound HTTPS requests, then forwards those requests to your
  web service over HTTP" ([Render's documentation](https://render.com/docs/web-services)); App
  Platform's `http_port` is the same shape, per its [app spec
  reference](https://docs.digitalocean.com/products/app-platform/reference/app-spec/) as of 2026-10.
  Plain HTTP reaching the node's listener is refused at the handshake. Fly's raw TCP ports would
  carry the node's own TLS, which is the one of the three that would fit, once the sidecar is
  solved.
- **App Platform and Render's free services keep no disk**, and the node's master key is a file
  under `/data` unless `HDTP_MASTER_KEY` is set (`internal/core/keyring.go`): a redeploy without
  a disk is a node that can no longer open its own leaf keys.

Each of these is a decision about the product (a two-process image, a plain-HTTP listener behind
a trusted edge, a key supplied from the platform's secrets), not a template that was forgotten.

## Cloudflare

Cloudflare is not a host for a Go server; the Tunnel is the Cloudflare path on any machine, the VM
paths above included. `compose.yaml` carries the `cloudflared` profile, and the quickstart's
[step 4](quickstart.md#4-set-the-address-people-will-reach-you-at) says what the node needs beside
it (the `cloudflare` adapter, its hostname, the sidecar setting, the LAN flag) and what edge mode
forces. Two nodes over two real tunnels were last run on 2026-09-18:
[docs/demos/cloudflare-two-users.md](demos/cloudflare-two-users.md).

## After the first boot

The first boot takes minutes. On the VM, `cloud-init status --wait` returns when it has finished;
every login after that shows the message of the day with these steps.

1. **Read the setup link out of the node's log**, as the service user, in the project directory:

   ```
   sudo -iu hdtp
   cd /opt/hdtp && docker compose logs hdtp-gateway | grep -A2 "setup"
   ```

   It prints `setup:   http://localhost:8080/setup?token=…`, valid until a passkey is registered,
   at most 24 hours (`passkey reset-wizard` mints another; the quickstart's
   [step 3](quickstart.md#3-register-your-passkey)).

2. **Open it through an SSH tunnel.** The portal is on the VM's loopback; from your own machine:

   ```
   ssh -L 8080:127.0.0.1:8080 <user>@<hostname>
   ```

   and open the setup link in your browser. Register the passkey; you are signed in.

3. **The public URL is already set**, from the environment, so the Settings field shows it locked
   and `account csr` knows the address. The identity, the signing request, your wallet's signature
   and the install are the quickstart's steps [5](quickstart.md#5-create-the-identity) to
   [7](quickstart.md#7-check-your-work), run in `/opt/hdtp` as `hdtp`; the one difference is that
   the wallet is on your machine and the node is not, so the request and the chain travel by `scp`:

   ```
   docker compose exec hdtp-gateway hdtp-gateway account create --slug me --name "Your Name"
   docker compose exec -T hdtp-gateway hdtp-gateway account csr --slug me > me.csr
   ```

   `scp` `me.csr` down, sign it (`hdtp id issue … --chain-out chain.pem`), `scp` `chain.pem` up, then:

   ```
   docker compose cp chain.pem hdtp-gateway:/tmp/chain.pem
   docker compose exec hdtp-gateway hdtp-gateway account install-leaf --slug me --chain /tmp/chain.pem
   docker compose exec hdtp-gateway hdtp-gateway doctor
   ```

   `doctor` reports the leaf, the sidecar answering, and — through Caddy — the probe line explained
   [above](#what-every-vm-path-does).

4. **Hand out your card and invite your first contact**: the quickstart's
   [step 8](quickstart.md#8-invite-your-first-contact).

## Changing or removing a deployment

The templates create a VM, not a service: a new release is `git fetch` and `git checkout` of the
tag in `/opt/hdtp` followed by `docker compose build && docker compose up -d`, the data volume
untouched. Removing the stack, the resource group, the instance or the Droplet removes the disk and
with it the node's keys, settings, contacts and audit trail; your wallet files are on your
machine and your root is not on the node at all (the quickstart's [last
section](quickstart.md#stopping-and-starting)).
