#!/usr/bin/env node
// The deploy templates' guard (docs/deploy.md): what only runs on a provider's machine goes stale
// silently, so every commit holds the templates under deploy/ to each other and to the node.
//
//   node scripts/deploy-check.mjs             # the gate (make deploy-check, part of make check)
//   node scripts/deploy-check.mjs --selftest  # plants one defect of each kind; each must be refused
//   node scripts/deploy-check.mjs --sync      # rewrites the copies of deploy/cloud-init.yaml that
//                                             # the AWS and Azure templates carry
//
// What it holds, and to what:
//   - deploy/cloud-init.yaml: a cloud-config; its two placeholders and nothing else written as a
//     dollar-brace; the compose override it writes names only services compose.yaml has plus
//     caddy, sets the node only environment names internal/core/config.go reads, pins the Caddy
//     image by digest as compose.yaml pins its images, and puts Caddy at the one address the node
//     is told to trust (HDTP_PROXY_ADDRESS); its Caddyfile dials the node's address and port, sets
//     the header internal/public/listener.go reads the caller's address from and drops the one it
//     reads a chain from; its runcmd fetches the release tag, vendors the sidecar's crates as the
//     Makefile's limitd-vendor does, in the Rust image the Dockerfile builds the sidecar with, and
//     holds Docker to the major docs/quickstart.md measured;
//   - deploy/aws/hdtp-gateway.cfn.json and deploy/azure/azuredeploy.json: the keys their formats
//     require (the minimal schemas below, each from the provider's public reference, cited), the
//     embedded cloud-init equal to the file byte for byte, every placeholder substituted from a
//     declared parameter, the Arm image and type, the ports, the record that gives the public host;
//   - deploy/gcp/deploy.sh and deploy/digitalocean/deploy.sh: the render script, the image family,
//     the user-data flag, the firewall ports; deploy/render-cloud-init.sh: every placeholder, and
//     the refusal of any other;
//   - every release tag the templates default to is one this repository has;
//   - docs/deploy.md: one status row per provider, each saying "not yet run" or dated; every
//     `make` target it cites exists; every repository path and every button URL names a file that
//     exists; README.md points at it.
//
// YAML is read by the subset parser at the bottom (block mappings and sequences, plain and quoted
// scalars, flow sequences of scalars, literal block scalars, comments): nothing under scripts/ or
// web/ parses YAML, and a dependency for a guard is not worth its surface. The templates are held
// to that subset; compose.yaml, which the node's own tests read with a full parser, is read here
// too, and --selftest proves the subset reads it as the full parser does on the facts used.
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const CLOUD_INIT = 'deploy/cloud-init.yaml'
const COMPOSE = 'compose.yaml'
const CFN = 'deploy/aws/hdtp-gateway.cfn.json'
const ARM = 'deploy/azure/azuredeploy.json'
const ARM_PARAMS = 'deploy/azure/azuredeploy.parameters.json'
const GCP = 'deploy/gcp/deploy.sh'
const GCP_README = 'deploy/gcp/README.md'
const DO = 'deploy/digitalocean/deploy.sh'
const RENDER = 'deploy/render-cloud-init.sh'
const DOC = 'docs/deploy.md'
const PLACEHOLDERS = ['Hostname', 'Release']
const SAMPLE = { Hostname: 'hdtp.example.com', Release: 'v0.0.0' }
const PROVIDERS = ['AWS', 'Azure', 'Google Cloud', 'DigitalOcean', 'Fly.io', 'Render', 'Cloudflare']
const REPO = 'https://github.com/humandelegatedtrustprotocol/hdtp-gateway'
const RAW = 'https://raw.githubusercontent.com/humandelegatedtrustprotocol/hdtp-gateway/main/'

/* ------------------------------------ the tree ------------------------------------ */

// What the checks read: files by repository path, and the tags. --selftest wraps this to plant.
function realTree() {
  return {
    read: (p) => readFileSync(join(root, p), 'utf8'),
    exists: (p) => existsSync(join(root, p)),
    tags: () => new Set(execFileSync('git', ['tag', '-l'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean)),
  }
}

/* ------------------------------------ the checks ------------------------------------ */

// check returns every problem it finds, each "<kind>: <what>", and throws nothing a template can
// cause: a file the subset parser refuses is a problem too.
export function check(tree) {
  const problems = []
  const fail = (kind, what) => problems.push(`${kind}: ${what}`)
  const guard = (kind, fn) => {
    try { fn() } catch (e) { fail(kind, e.message) }
  }

  const envNames = configEnvNames(tree.read('internal/core/config.go'))
  const publicBind = readConst(tree.read('internal/core/config.go'), /PublicBind:\s+"([^"]+)"/, 'the default PublicBind')
  const nodePort = publicBind.slice(publicBind.lastIndexOf(':') + 1)
  const listener = tree.read('internal/public/listener.go')
  const certHeader = readConst(listener, /ProxyCertHeader\s+=\s+"([^"]+)"/, 'ProxyCertHeader')
  const addressHeader = readConst(listener, /ProxyAddressHeader\s+=\s+"([^"]+)"/, 'ProxyAddressHeader')
  const makefile = tree.read('Makefile')
  const limitdDir = readConst(makefile, /^LIMITD := (.+)$/m, 'LIMITD')
  const vendorDir = readConst(makefile, /^LIMITD_VENDOR := (.+)$/m, 'LIMITD_VENDOR')
  const rustTag = readConst(tree.read('Dockerfile'), /^FROM (rust:[^\s]+) AS limitd$/m, "the Dockerfile's limitd stage image")
  const dockerMajor = readConst(tree.read('docs/quickstart.md'), /Docker (\d+)\.\d+\.\d+/, 'the Docker version the quickstart measured')

  const text = tree.read(CLOUD_INIT)
  let ci = null
  guard(CLOUD_INIT, () => { ci = parseYAML(text, CLOUD_INIT) })
  if (!text.startsWith('#cloud-config\n')) fail(CLOUD_INIT, 'the first line is not #cloud-config, so cloud-init would not read it as a cloud-config')

  // Placeholders: the two, and no other dollar-brace anywhere.
  const found = new Set([...text.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]))
  for (const p of PLACEHOLDERS) if (!found.has(p)) fail(CLOUD_INIT, `the placeholder ${p} is never used`)
  for (const f of found) if (!PLACEHOLDERS.includes(f)) fail(CLOUD_INIT, `\${${f}} is not a placeholder any template substitutes; it would reach a VM as text`)
  const rendered = render(text, SAMPLE)
  if (rendered.includes('${')) fail(CLOUD_INIT, 'a dollar-brace is left after substituting the placeholders')
  if (!rendered.includes(`https://${SAMPLE.Hostname}`)) fail(CLOUD_INIT, 'the rendered public URL does not name the hostname')

  if (ci) {
    const files = Object.fromEntries((ci.write_files || []).map((f) => [f.path, f]))
    const need = ['/opt/hdtp/.env', '/opt/hdtp/compose.override.yaml', '/opt/hdtp/caddy/Caddyfile', '/etc/update-motd.d/99-hdtp-gateway', '/etc/apt/preferences.d/docker']
    for (const p of need) {
      const f = files[p]
      if (!f) fail(CLOUD_INIT, `write_files does not write ${p}`)
      else if (typeof f.content !== 'string' || !/^"?0[0-7]{3}"?$/.test(String(f.permissions))) fail(CLOUD_INIT, `${p} needs content and permissions (an octal string)`)
    }
    if (files['/etc/update-motd.d/99-hdtp-gateway'] && String(files['/etc/update-motd.d/99-hdtp-gateway'].permissions) !== '0755') fail(CLOUD_INIT, 'the motd script is not executable (permissions 0755)')

    // .env: what the override and the Caddyfile read.
    const env = Object.fromEntries((files['/opt/hdtp/.env']?.content || '').split('\n').filter(Boolean).map((l) => l.split('=', 2).length === 2 ? [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)] : [l, '']))
    if (env.HDTP_PUBLIC_URL !== 'https://${Hostname}') fail(CLOUD_INIT, '.env must set HDTP_PUBLIC_URL=https://${Hostname}: the certificate names that address')
    if (env.HDTP_HOSTNAME !== '${Hostname}') fail(CLOUD_INIT, '.env must set HDTP_HOSTNAME=${Hostname}: the name Caddy serves')
    if (!envNames.has('HDTP_PUBLIC_URL')) fail(CLOUD_INIT, 'the node no longer reads HDTP_PUBLIC_URL')

    // The override, held to compose.yaml and to the node.
    let override = null
    let compose = null
    guard(CLOUD_INIT, () => { override = parseYAML(files['/opt/hdtp/compose.override.yaml']?.content || '', 'compose.override.yaml') })
    guard(COMPOSE, () => { compose = parseYAML(tree.read(COMPOSE), COMPOSE) })
    const caddyfile = files['/opt/hdtp/caddy/Caddyfile']?.content || ''
    if (override && compose) {
      const known = new Set([...Object.keys(compose.services || {}), 'caddy'])
      for (const s of Object.keys(override.services || {})) if (!known.has(s)) fail(CLOUD_INIT, `the override names a service compose.yaml has not got: ${s}`)
      const node = override.services?.['hdtp-gateway']
      const caddy = override.services?.caddy
      if (!node || !caddy) fail(CLOUD_INIT, 'the override must configure hdtp-gateway and run caddy')
      else {
        for (const k of Object.keys(node.environment || {})) if (!envNames.has(k)) fail(CLOUD_INIT, `the override sets ${k}, which internal/core/config.go does not read`)
        if (node.environment?.HDTP_PUBLIC_URL !== '$HDTP_PUBLIC_URL') fail(CLOUD_INIT, 'the override must pass HDTP_PUBLIC_URL from .env to the node')
        const nodeIP = node.networks?.edge?.ipv4_address
        const caddyIP = caddy.networks?.edge?.ipv4_address
        const proxy = node.environment?.HDTP_PROXY_ADDRESS
        if (!nodeIP || !caddyIP) fail(CLOUD_INIT, 'the node and caddy need fixed addresses on the edge network: HDTP_PROXY_ADDRESS is one address')
        if (proxy !== caddyIP) fail(CLOUD_INIT, `HDTP_PROXY_ADDRESS is ${proxy}; caddy is at ${caddyIP}, and the node reads the caller's address from that one source`)
        const subnet = override.networks?.edge?.ipam?.config?.[0]?.subnet
        if (!subnet || !inSubnet24(nodeIP, subnet) || !inSubnet24(caddyIP, subnet)) fail(CLOUD_INIT, `the edge network's subnet ${subnet} must hold both addresses`)
        const image = String(caddy.image || '')
        if (!PINNED.test(image)) fail(CLOUD_INIT, `caddy's image is not pinned by digest with its tag kept, as compose.yaml pins its images: ${image}`)
        for (const want of ['80:80', '443:443']) if (!(caddy.ports || []).includes(want)) fail(CLOUD_INIT, `caddy does not publish ${want}`)
        if (!(caddy.volumes || []).includes('/opt/hdtp/caddy/Caddyfile:/etc/caddy/Caddyfile:ro')) fail(CLOUD_INIT, 'caddy does not mount the written Caddyfile at /etc/caddy/Caddyfile')
        for (const dir of ['/data', '/config']) if (!(caddy.volumes || []).some((v) => String(v).endsWith(`:${dir}`))) fail(CLOUD_INIT, `caddy keeps certificates under ${dir}; the override gives it no volume there`)
        if (caddy.environment?.HDTP_HOSTNAME !== '$HDTP_HOSTNAME') fail(CLOUD_INIT, 'caddy must get HDTP_HOSTNAME from .env: the Caddyfile serves {$HDTP_HOSTNAME}')
        // The Caddyfile: the node's address and port, the two headers, the server name.
        const upstream = caddyfile.match(/reverse_proxy https:\/\/([0-9.]+):(\d+)/)
        if (!upstream) fail(CLOUD_INIT, 'the Caddyfile does not reverse_proxy to an https://<address>:<port> upstream')
        else {
          if (upstream[1] !== nodeIP) fail(CLOUD_INIT, `the Caddyfile dials ${upstream[1]}; the node is at ${nodeIP}`)
          if (upstream[2] !== nodePort) fail(CLOUD_INIT, `the Caddyfile dials port ${upstream[2]}; the node's public bind is ${publicBind}`)
        }
        if (!caddyfile.includes(`header_up ${addressHeader} {remote_host}`)) fail(CLOUD_INIT, `the Caddyfile must set ${addressHeader} to the caller's address ({remote_host}): the node reads it from Caddy's address`)
        if (!caddyfile.includes(`header_up -${certHeader}`)) fail(CLOUD_INIT, `the Caddyfile must drop ${certHeader}: Caddy forwards no chain, and the node must not read one the caller wrote`)
        if (!caddyfile.includes('tls_insecure_skip_verify') || !caddyfile.includes('tls_server_name {$HDTP_HOSTNAME}')) fail(CLOUD_INIT, 'the Caddyfile carries each request to the node over TLS without validation, naming the hostname: the node presents its identities\' chains')
        if (!caddyfile.startsWith('{$HDTP_HOSTNAME} {')) fail(CLOUD_INIT, 'the Caddyfile must serve the hostname from .env, {$HDTP_HOSTNAME}')
      }
    }

    // Docker held to one major, the one the quickstart measured.
    const pin = files['/etc/apt/preferences.d/docker']?.content || ''
    if (!pin.includes(`Pin: version 5:${dockerMajor}.*`)) fail(CLOUD_INIT, `the apt pin does not hold docker-ce to major ${dockerMajor}, the one docs/quickstart.md measured`)

    // runcmd: the fetch, the vendor step as the Makefile does it, the build and the start.
    const cmds = (ci.runcmd || []).map(String)
    const has = (s) => cmds.some((c) => c.includes(s))
    if (!has(`git remote add origin ${REPO}.git`) || !has('git fetch -q --depth 1 origin tag ${Release}') || !has('git checkout -q ${Release}')) fail(CLOUD_INIT, `runcmd must fetch the release tag from ${REPO}`)
    const vendor = `cargo vendor --locked --manifest-path ${limitdDir}/Cargo.toml ${vendorDir}/crates > ${vendorDir}/config.toml`
    if (!has(vendor)) fail(CLOUD_INIT, `runcmd must vendor the sidecar's crates as make limitd-vendor does: ${vendor}`)
    if (!has(`docker run --rm -e CARGO_NET_GIT_FETCH_WITH_CLI=true -v /opt/hdtp:/src -w /src ${rustTag} `)) fail(CLOUD_INIT, `the vendor step must run in ${rustTag}, the Dockerfile's sidecar stage image, with the Makefile's git setting`)
    if (!has('docker compose build && docker compose up -d')) fail(CLOUD_INIT, 'runcmd must build and start the compose project')
    if (!has('apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin')) fail(CLOUD_INIT, 'runcmd must install Docker\'s packages as docs.docker.com names them')
    if (!has('https://download.docker.com/linux/ubuntu/gpg')) fail(CLOUD_INIT, "runcmd must fetch Docker's apt key from download.docker.com")
    if (!has('usermod -aG docker hdtp') || !has('useradd --system')) fail(CLOUD_INIT, 'runcmd must create the service user hdtp in the docker group')

    // The login message: where the setup link is, and how to reach the portal.
    const motd = files['/etc/update-motd.d/99-hdtp-gateway']?.content || ''
    for (const s of ['docker compose logs hdtp-gateway', '/setup?token=', 'ssh -L 8080:127.0.0.1:8080', 'cloud-init status']) if (!motd.includes(s)) fail(CLOUD_INIT, `the login message does not say: ${s}`)
    if (typeof ci.final_message !== 'string') fail(CLOUD_INIT, 'no final_message: the console would not say the first boot finished')
  }

  // The release every template defaults to: one tag, and one this repository has.
  const releases = {}
  guard(CFN, () => { releases[CFN] = JSON.parse(tree.read(CFN)).Parameters?.Release?.Default })
  guard(ARM, () => { releases[ARM] = JSON.parse(tree.read(ARM)).parameters?.release?.defaultValue })
  for (const s of [GCP, DO]) guard(s, () => { releases[s] = tree.read(s).match(/HDTP_RELEASE:-(v[0-9.]+)/)?.[1] })
  const tags = tree.tags()
  for (const [file, tag] of Object.entries(releases)) {
    if (!tag) fail(file, 'no default release tag')
    else if (!tags.has(tag)) fail(file, `defaults to ${tag}, which is not a tag of this repository`)
  }
  if (new Set(Object.values(releases)).size !== 1) fail('release', `the templates default to different releases: ${JSON.stringify(releases)}`)

  guard(CFN, () => checkCloudFormation(JSON.parse(tree.read(CFN)), text, fail))
  guard(ARM, () => checkARM(JSON.parse(tree.read(ARM)), JSON.parse(tree.read(ARM_PARAMS)), text, fail))
  guard(GCP, () => checkShell(tree, fail))
  guard(RENDER, () => {
    const s = tree.read(RENDER)
    for (const p of PLACEHOLDERS) if (!s.includes(`'\${${p}}'`)) fail(RENDER, `does not substitute \${${p}}`)
    if (!s.includes(`*'\${'*`)) fail(RENDER, 'does not refuse a placeholder left in its output')
  })
  guard(DOC, () => checkDocs(tree, fail, makefile))
  return problems
}

// The AWS template, held to the CloudFormation template anatomy and the resource types it uses
// (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html;
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html
// for the SSM parameter type; https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-sub.html
// for Fn::Sub, whose String takes no function, which is why the cloud-init is a Fn::Join of lines).
function checkCloudFormation(t, cloudInit, fail) {
  if (t.AWSTemplateFormatVersion !== '2010-09-09') fail(CFN, 'AWSTemplateFormatVersion is not 2010-09-09')
  const params = t.Parameters || {}
  for (const p of ['Hostname', 'HostedZoneId', 'InstanceType', 'KeyName', 'SshCidr', 'Release', 'Ami']) if (!params[p]?.Type) fail(CFN, `no parameter ${p}`)
  if (params.HostedZoneId?.Type !== 'AWS::Route53::HostedZone::Id') fail(CFN, 'HostedZoneId must be an AWS::Route53::HostedZone::Id, so the console offers the zones')
  if (params.Ami?.Type !== 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>') fail(CFN, 'Ami must resolve from SSM (AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>)')
  if (!String(params.Ami?.Default || '').endsWith('/arm64/hvm/ebs-gp3/ami-id') || !String(params.Ami?.Default || '').startsWith('/aws/service/canonical/ubuntu/server/')) fail(CFN, "Ami's default is not Canonical's arm64 Ubuntu parameter path")
  if (!/^[a-z]+[0-9]+g[a-z]*\./.test(String(params.InstanceType?.Default || ''))) fail(CFN, `InstanceType defaults to ${params.InstanceType?.Default}, not an Arm (Graviton) type; the AMI is arm64`)
  if (params.SshCidr?.Default !== undefined) fail(CFN, 'SshCidr must have no default: an open port 22 is a choice the person makes')
  const res = t.Resources || {}
  const byType = (ty) => Object.entries(res).filter(([, r]) => r.Type === ty)
  const [inst] = byType('AWS::EC2::Instance')
  if (!inst) fail(CFN, 'no AWS::EC2::Instance')
  else {
    const props = inst[1].Properties || {}
    if (props.ImageId?.Ref !== 'Ami') fail(CFN, 'the instance does not take its ImageId from the Ami parameter')
    const join = props.UserData?.['Fn::Base64']?.['Fn::Join']
    if (!Array.isArray(join) || join[0] !== '\n' || !Array.isArray(join[1])) fail(CFN, 'UserData must be Fn::Base64 of a Fn::Join of lines with "\\n"')
    else {
      const lines = []
      join[1].forEach((l, i) => {
        if (typeof l === 'string') {
          if (l.includes('${')) fail(CFN, `UserData line ${i + 1} holds a placeholder but is not a Fn::Sub, so it would reach the instance as text`)
          lines.push(l)
        } else if (l && typeof l['Fn::Sub'] === 'string') {
          for (const m of l['Fn::Sub'].matchAll(/\$\{([^}]*)\}/g)) {
            if (!m[1].startsWith('AWS::') && !params[m[1]]) fail(CFN, `UserData line ${i + 1} substitutes \${${m[1]}}, which is not a parameter`)
          }
          lines.push(l['Fn::Sub'])
        } else {
          fail(CFN, `UserData line ${i + 1} is neither a string nor a Fn::Sub`)
          lines.push('')
        }
      })
      if (lines.join('\n') + '\n' !== cloudInit) fail(CFN, `the embedded cloud-init differs from ${CLOUD_INIT}: run node scripts/deploy-check.mjs --sync`)
    }
    if (!Array.isArray(props.SecurityGroupIds) || props.SecurityGroupIds.length === 0) fail(CFN, 'the instance has no security group')
  }
  const [sg] = byType('AWS::EC2::SecurityGroup')
  if (!sg) fail(CFN, 'no AWS::EC2::SecurityGroup')
  else {
    const rules = sg[1].Properties?.SecurityGroupIngress || []
    const open = (port, proto = 'tcp') => rules.some((r) => r.IpProtocol === proto && r.FromPort === port && r.ToPort === port && r.CidrIp === '0.0.0.0/0')
    if (!open(80) || !open(443)) fail(CFN, 'the security group must open tcp 80 and 443 to everyone: Caddy answers ACME on both and the node is public')
    if (!rules.some((r) => r.IpProtocol === 'tcp' && r.FromPort === 22 && r.CidrIp?.Ref === 'SshCidr')) fail(CFN, 'the security group must open 22 to SshCidr and nothing wider')
  }
  const [eip] = byType('AWS::EC2::EIP')
  if (!eip || eip[1].Properties?.InstanceId?.Ref !== inst?.[0]) fail(CFN, 'no AWS::EC2::EIP on the instance: the record needs a fixed address')
  const [rec] = byType('AWS::Route53::RecordSet')
  if (!rec) fail(CFN, 'no AWS::Route53::RecordSet: nothing gives the hostname an address')
  else {
    const p = rec[1].Properties || {}
    if (p.Type !== 'A' || p.HostedZoneId?.Ref !== 'HostedZoneId' || p.Name?.['Fn::Sub'] !== '${Hostname}.' || p.ResourceRecords?.[0]?.Ref !== eip?.[0]) fail(CFN, 'the record must be an A record for ${Hostname}. in HostedZoneId pointing at the Elastic IP')
  }
  if (t.Outputs?.URL?.Value?.['Fn::Sub'] !== 'https://${Hostname}') fail(CFN, 'the URL output must be https://${Hostname}')
}

// The Azure template, held to the ARM template anatomy (https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/syntax),
// the resources it uses (https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines;
// https://learn.microsoft.com/en-us/azure/templates/microsoft.network/publicipaddresses), the
// arm64 Ubuntu image (https://ubuntu.com/azure/docs/en/latest/azure-how-to/instances/find-ubuntu-images/)
// and the DNS label's name form (https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses).
function checkARM(t, p, cloudInit, fail) {
  if (t.$schema !== 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#') fail(ARM, '$schema is not the 2019-04-01 deploymentTemplate schema')
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(String(t.contentVersion))) fail(ARM, 'contentVersion is not a.b.c.d')
  const params = t.parameters || {}
  for (const name of ['dnsLabel', 'hostname', 'adminUsername', 'sshPublicKey', 'sshSourceAddressPrefix', 'vmSize', 'release', 'location']) if (!params[name]?.type) fail(ARM, `no parameter ${name}`)
  if (params.hostname?.defaultValue !== '') fail(ARM, "hostname must default to empty: the DNS label's name is the default")
  if (params.sshSourceAddressPrefix?.defaultValue !== undefined) fail(ARM, 'sshSourceAddressPrefix must have no default: an open port 22 is a choice the person makes')
  if (!/^Standard_[DE]\d+p/.test(String(params.vmSize?.defaultValue || ''))) fail(ARM, `vmSize defaults to ${params.vmSize?.defaultValue}, not an Arm (Ampere, "p") size; the image is server-arm64`)
  if (t.variables?.cloudInit !== cloudInit) fail(ARM, `variables.cloudInit differs from ${CLOUD_INIT}: run node scripts/deploy-check.mjs --sync`)
  const res = t.resources || []
  const byType = (ty) => res.filter((r) => r.type === ty)
  const [vm] = byType('Microsoft.Compute/virtualMachines')
  if (!vm) fail(ARM, 'no Microsoft.Compute/virtualMachines')
  else {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(vm.apiVersion))) fail(ARM, 'the VM has no apiVersion')
    const img = vm.properties?.storageProfile?.imageReference || {}
    if (img.publisher !== 'Canonical' || img.offer !== 'ubuntu-24_04-lts' || img.sku !== 'server-arm64' || img.version !== 'latest') fail(ARM, `the image is not Canonical:ubuntu-24_04-lts:server-arm64:latest: ${JSON.stringify(img)}`)
    const custom = String(vm.properties?.osProfile?.customData || '')
    if (!custom.startsWith('[base64(') || !custom.includes("variables('cloudInit')")) fail(ARM, 'customData must be base64 of variables(\'cloudInit\') with the placeholders replaced')
    for (const ph of PLACEHOLDERS) if (!custom.includes(`'\${${ph}}'`)) fail(ARM, `customData does not replace \${${ph}}`)
    if (!custom.includes("parameters('release')")) fail(ARM, "customData must take the release from parameters('release')")
    if (vm.properties?.osProfile?.linuxConfiguration?.disablePasswordAuthentication !== true) fail(ARM, 'password login must be off')
    // The one choice of name, written once and used thrice: the first boot, and the two outputs.
    const choice = "if(empty(parameters('hostname')), reference(resourceId('Microsoft.Network/publicIPAddresses', variables('publicIpName'))).dnsSettings.fqdn, parameters('hostname'))"
    if (!custom.includes(`'\${Hostname}', ${choice}`)) fail(ARM, "the hostname must be parameters('hostname'), or the public IP's own DNS name when it is empty")
    for (const out of ['hostname', 'url']) if (!String(t.outputs?.[out]?.value || '').includes(choice)) fail(ARM, `the ${out} output must make the same choice of name customData makes`)
    if (!String(t.outputs?.publicIp?.value || '').includes('.ipAddress')) fail(ARM, "no publicIp output: a name of one's own needs the address to point at")
  }
  const [ip] = byType('Microsoft.Network/publicIPAddresses')
  if (!ip) fail(ARM, 'no Microsoft.Network/publicIPAddresses')
  else {
    if (ip.sku?.name !== 'Standard' || ip.properties?.publicIPAllocationMethod !== 'Static') fail(ARM, 'the public IP must be Standard and Static (Basic is retired)')
    if (ip.properties?.dnsSettings?.domainNameLabel !== "[parameters('dnsLabel')]") fail(ARM, "the public IP's DNS label must be parameters('dnsLabel'): that label is the hostname")
  }
  const [nsg] = byType('Microsoft.Network/networkSecurityGroups')
  if (!nsg) fail(ARM, 'no Microsoft.Network/networkSecurityGroups: a Standard public IP is closed without one')
  else {
    const rules = nsg.properties?.securityRules || []
    const rule = (port) => rules.find((r) => r.properties?.destinationPortRange === String(port) && r.properties?.direction === 'Inbound' && r.properties?.access === 'Allow')
    for (const port of [80, 443]) if (rule(port)?.properties?.sourceAddressPrefix !== '*') fail(ARM, `the security group must open ${port} to everyone`)
    if (rule(22)?.properties?.sourceAddressPrefix !== "[parameters('sshSourceAddressPrefix')]") fail(ARM, 'the security group must open 22 to sshSourceAddressPrefix and nothing wider')
  }
  // The parameters file: the shape, names the template has, and no secret.
  if (p.$schema !== 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#') fail(ARM_PARAMS, '$schema is not the 2019-04-01 deploymentParameters schema')
  for (const [name, v] of Object.entries(p.parameters || {})) {
    if (!params[name]) fail(ARM_PARAMS, `names ${name}, which the template has not got`)
    if (String(v?.value ?? '').includes('-----BEGIN')) fail(ARM_PARAMS, `${name} holds key material; a sample file carries none`)
  }
}

// The two shell paths, held to the flags their CLIs document
// (https://docs.cloud.google.com/sdk/gcloud/reference/compute/instances/create;
// https://docs.digitalocean.com/reference/doctl/reference/compute/droplet/create/) and to the
// Ubuntu 24.04 arm64 image family (https://docs.cloud.google.com/compute/docs/images/os-details).
function checkShell(tree, fail) {
  const gcp = tree.read(GCP)
  for (const s of ['set -euo pipefail', '/../render-cloud-init.sh" "$hostname" "$release"', '--image-family=ubuntu-2404-lts-arm64', '--image-project=ubuntu-os-cloud', '--metadata-from-file=user-data="$userdata"', '--rules=tcp:80,tcp:443', '--machine-type="$machine"', 'HDTP_MACHINE:-t2a-', 'networkInterfaces[0].accessConfigs[0].natIP', '-L 8080:127.0.0.1:8080']) {
    if (!gcp.includes(s)) fail(GCP, `does not contain: ${s}`)
  }
  if (!tree.exists(GCP_README)) fail(GCP, `${GCP_README}, the Cloud Shell walkthrough the button opens, does not exist`)
  const dO = tree.read(DO)
  for (const s of ['set -euo pipefail', '/../render-cloud-init.sh" "$hostname" "$release"', 'doctl compute droplet create', '--user-data-file "$userdata"', '--image "$image"', 'HDTP_IMAGE:-ubuntu-24-04-x64', '--format PublicIPv4', '-L 8080:127.0.0.1:8080']) {
    if (!dO.includes(s)) fail(DO, `does not contain: ${s}`)
  }
}

// docs/deploy.md, held to the files and targets it names.
function checkDocs(tree, fail, makefile) {
  const doc = tree.read(DOC)
  const targets = new Set([...makefile.matchAll(/^([a-z][a-z0-9-]*):/gm)].map((m) => m[1]))
  for (const m of doc.matchAll(/`make ([a-z][a-z0-9-]*)/g)) if (!targets.has(m[1])) fail(DOC, `cites make ${m[1]}, which the Makefile has not got`)
  if (!doc.includes('`make deploy-check`')) fail(DOC, 'does not say what validated the templates (make deploy-check)')
  // The status table: one row per provider, each not yet run or dated.
  const rows = doc.split('\n').filter((l) => l.startsWith('| '))
  for (const provider of PROVIDERS) {
    const row = rows.find((l) => l.startsWith(`| ${provider} |`))
    if (!row) fail(DOC, `the status table has no row for ${provider}`)
    else if (!/not yet run|no template/.test(row) && !/\b20\d\d-\d\d-\d\d\b/.test(row)) fail(DOC, `${provider}'s row neither says "not yet run" or "no template" nor carries a date`)
  }
  // Every repository path named in a code span or a link exists.
  const paths = new Set()
  for (const m of doc.matchAll(/`((?:deploy|docs|scripts)\/[^`\s]+|compose\.yaml|Dockerfile)`/g)) paths.add(m[1])
  for (const m of doc.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1]
    if (target.startsWith(RAW)) paths.add(target.slice(RAW.length))
    else if (target.includes('cloudshell_tutorial=')) paths.add(decodeURIComponent(target.split('cloudshell_tutorial=')[1].split('&')[0]))
    else if (target.startsWith('https://portal.azure.com/#create/Microsoft.Template/uri/')) {
      const raw = decodeURIComponent(target.slice('https://portal.azure.com/#create/Microsoft.Template/uri/'.length))
      if (!raw.startsWith(RAW)) fail(DOC, `the Azure button does not point at a raw URL of this repository's main: ${raw}`)
      else paths.add(raw.slice(RAW.length))
    } else if (!target.includes('://') && !target.startsWith('#')) paths.add(join('docs', target.split('#')[0]))
  }
  for (const p of paths) if (!tree.exists(p)) fail(DOC, `names ${p}, which does not exist`)
  if (!tree.read('README.md').includes('](docs/deploy.md)')) fail('README.md', 'does not point at docs/deploy.md')
}

/* ------------------------------------ helpers ------------------------------------ */

// Every HDTP_* name internal/core/config.go reads from the environment: the envStr calls and the
// lookup calls, which is how the file declares them.
export function configEnvNames(source) {
  const names = new Set([...source.matchAll(/(?:envStr|lookup)\("(HDTP_[A-Z0-9_]+)"/g)].map((m) => m[1]))
  if (names.size < 10) throw new Error(`internal/core/config.go: read only ${names.size} environment names; the declaration pattern has changed`)
  return names
}

function readConst(source, re, what) {
  const m = source.match(re)
  if (!m) throw new Error(`could not read ${what}`)
  return m[1]
}

// A tag kept beside a digest: the way compose.yaml pins portal and cloudflared.
const PINNED = /^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$/

function render(text, values) {
  return text.replace(/\$\{([^}]*)\}/g, (m, name) => (name in values ? values[name] : m))
}

function inSubnet24(ip, subnet) {
  const m = String(subnet).match(/^(\d+\.\d+\.\d+)\.0\/24$/)
  return !!m && String(ip).startsWith(m[1] + '.')
}

/* ------------------------------------ --sync ------------------------------------ */

function sync() {
  const text = readFileSync(join(root, CLOUD_INIT), 'utf8')
  const lines = text.replace(/\n$/, '').split('\n').map((l) => (l.includes('${') ? { 'Fn::Sub': l } : l))
  const cfn = JSON.parse(readFileSync(join(root, CFN), 'utf8'))
  const inst = Object.values(cfn.Resources).find((r) => r.Type === 'AWS::EC2::Instance')
  inst.Properties.UserData = { 'Fn::Base64': { 'Fn::Join': ['\n', lines] } }
  writeFileSync(join(root, CFN), JSON.stringify(cfn, null, 2) + '\n')
  const arm = JSON.parse(readFileSync(join(root, ARM), 'utf8'))
  arm.variables.cloudInit = text
  writeFileSync(join(root, ARM), JSON.stringify(arm, null, 2) + '\n')
  console.log(`deploy-check: ${CFN} and ${ARM} carry ${CLOUD_INIT} (${lines.length} lines)`)
}

/* ------------------------------------ --selftest ------------------------------------ */

// Each plant edits one input in memory and must be refused with a problem of the named kind.
function selftest() {
  const real = realTree()
  const green = check(real)
  if (green.length) {
    console.error('selftest: the tree must be green before planting:\n  ' + green.join('\n  '))
    process.exit(1)
  }
  // The subset parser on the full parser's facts: compose.yaml as internal/integrationtest reads it.
  const compose = parseYAML(real.read(COMPOSE), COMPOSE)
  const facts = [
    [Object.keys(compose.services).join(','), 'init-data,hdtp-gateway,limitd,portal,postgres,cloudflared'],
    [compose.services['hdtp-gateway'].ports[0], '127.0.0.1:8080:8081'],
    [compose.services.portal.network_mode, 'service:hdtp-gateway'],
    [compose.services.limitd.command.join(' '), '-config /etc/hdtp-limitd/limits.json'],
    [compose.services.postgres.profiles[0], 'postgres'],
    [compose.services.postgres.environment.POSTGRES_PASSWORD, '${POSTGRES_PASSWORD:-}'],
    [compose.services['init-data'].restart, 'no'],
    [String(PINNED.test(compose.services.portal.image)), 'true'],
    [Object.keys(compose.volumes).join(','), 'hdtp-data,hdtp-pg'],
  ]
  for (const [got, want] of facts) {
    if (got !== want) {
      console.error(`selftest: the YAML subset parser read compose.yaml wrong: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`)
      process.exit(1)
    }
  }
  const edit = (file, from, to, kind, what) => ({ file, kind, what, apply: (s) => { if (!s.includes(from)) throw new Error(`plant "${what}": ${file} has no ${JSON.stringify(from)}`); return s.replace(from, to) } })
  const plants = [
    edit(CLOUD_INIT, '#cloud-config\n', '#!/bin/sh\n', CLOUD_INIT, 'not a cloud-config'),
    edit(CLOUD_INIT, 'HDTP_PUBLIC_URL=https://${Hostname}', 'HDTP_PUBLIC_URL=https://${Host}', CLOUD_INIT, 'a placeholder no template substitutes'),
    edit(CLOUD_INIT, '        caddy:\n', '        envoy:\n          image: envoyproxy/envoy\n        caddy:\n', CLOUD_INIT, 'a service compose.yaml has not got'),
    edit(CLOUD_INIT, '            HDTP_PROXY_ADDRESS: 172.30.41.10\n', '            HDTP_PROXY_ADDRESS: 172.30.41.10\n            HDTP_RELAY_MODE: on\n', CLOUD_INIT, 'an environment name the node does not read'),
    edit(CLOUD_INIT, 'image: caddy:2-alpine@sha256:', 'image: caddy:2-alpine #', CLOUD_INIT, 'the Caddy image not pinned by digest'),
    edit(CLOUD_INIT, 'HDTP_PROXY_ADDRESS: 172.30.41.10', 'HDTP_PROXY_ADDRESS: 172.30.41.11', CLOUD_INIT, 'the node trusting an address that is not Caddy'),
    edit(CLOUD_INIT, 'header_up X-HDTP-Client-Address {remote_host}', 'header_up X-Forwarded-For {remote_host}', CLOUD_INIT, "the caller's address in a header the node does not read"),
    edit(CLOUD_INIT, 'header_up -X-Forwarded-Client-Cert', 'header_up -X-Client-Cert', CLOUD_INIT, "a caller's forged chain header reaching the node"),
    edit(CLOUD_INIT, 'reverse_proxy https://172.30.41.20:8443', 'reverse_proxy https://172.30.41.20:8080', CLOUD_INIT, "Caddy dialling the portal's port instead of the node's"),
    edit(CLOUD_INIT, 'rust:1.92-alpine', 'rust:1.80-alpine', CLOUD_INIT, 'the vendor step in another Rust image than the Dockerfile\'s'),
    edit(CLOUD_INIT, 'Pin: version 5:29.*', 'Pin: version 5:28.*', CLOUD_INIT, 'Docker held to a major the quickstart did not measure'),
    edit(CLOUD_INIT, 'docker compose logs hdtp-gateway | grep', 'docker ps | grep', CLOUD_INIT, 'a login message that does not say where the setup link is'),
    edit(CLOUD_INIT, '            - "443:443"\n            - "443:443/udp"\n', '            - "443:443/udp"\n', CLOUD_INIT, 'Caddy not published on 443'),
    edit(CLOUD_INIT, '      HDTP_HOSTNAME=${Hostname}\n', '\tHDTP_HOSTNAME=${Hostname}\n', CLOUD_INIT, 'a tab, outside the YAML subset'),
    edit(CLOUD_INIT, '  - chmod a+r /etc/apt/keyrings/docker.asc\n', "  - printf 'Types: deb' > /tmp/x\n", CLOUD_INIT, 'a runcmd line YAML reads as a mapping, not a command'),
    edit(CFN, '"Default": "v0.1.1"', '"Default": "v9.9.9"', CFN, 'a release tag the repository has not got'),
    edit(CFN, '"FromPort": 443,\n            "ToPort": 443,\n            "CidrIp": "0.0.0.0/0"\n          },\n          {\n            "IpProtocol": "udp"', '"FromPort": 443,\n            "ToPort": 443,\n            "CidrIp": "10.0.0.0/8"\n          },\n          {\n            "IpProtocol": "udp"', CFN, '443 not open to everyone'),
    edit(CFN, '"AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>"', '"String"', CFN, 'an AMI typed by hand'),
    edit(CFN, '"Default": "t4g.medium"', '"Default": "t3.medium"', CFN, 'an x86 instance type for an arm64 AMI'),
    edit(CFN, '"Fn::Sub": "      HDTP_PUBLIC_URL=https://${Hostname}"', '"Fn::Sub": "      HDTP_PUBLIC_URL=https://${Host}"', CFN, 'an embedded line substituting a name that is not a parameter'),
    edit(CFN, '"      HDTP_HOSTNAME=${Hostname}"', '"      HDTP_HOSTNAME=${Hostname}"', CFN, 'placeholder: set below'),
    edit(ARM, '"sku": "server-arm64"', '"sku": "server"', ARM, 'an x64 image for an Arm size'),
    edit(ARM, "'${Release}', parameters('release')", "'${Tag}', parameters('release')", ARM, 'a placeholder customData does not replace'),
    edit(ARM, '"defaultValue": "Standard_D2ps_v5"', '"defaultValue": "Standard_D2s_v5"', ARM, 'an x64 size for the arm64 image'),
    edit(ARM, "\"value\": \"[concat('https://', if(empty(parameters('hostname'))", "\"value\": \"[concat('https://', if(empty(parameters('dnsLabel'))", ARM, 'an output choosing the name differently from the first boot'),
    edit(ARM_PARAMS, '"value": "ssh-ed25519 AAAA... your public key, one line"', '"value": "-----BEGIN OPENSSH PRIVATE KEY-----"', ARM_PARAMS, 'key material in the sample parameters'),
    edit(GCP, '--metadata-from-file=user-data="$userdata"', '--metadata-from-file=startup-script="$userdata"', GCP, 'the cloud-init handed to GCE under the wrong key'),
    edit(DO, 'HDTP_IMAGE:-ubuntu-24-04-x64', 'HDTP_IMAGE:-ubuntu-20-04-x64', DO, 'another Ubuntu than the one the first boot was written for'),
    edit(RENDER, `if [[ "$out" == *'\${'* ]]; then`, 'if false; then', RENDER, 'the render script no longer refusing a placeholder left behind'),
    edit(DOC, '`make deploy-check`', '`make deploy-validate`', DOC, 'a make target the Makefile has not got'),
    edit(DOC, 'deploy/aws/hdtp-gateway.cfn.json', 'deploy/aws/hdtp-gateway.cfn.yaml', DOC, 'a file that does not exist'),
    edit(DOC, '| Azure |', '| Azure Stack |', DOC, 'a provider without a status row'),
    edit('README.md', '](docs/deploy.md)', '](docs/deploying.md)', 'README.md', 'the README pointing nowhere'),
  ]
  // The two embedded copies drifting from the file, one line each: a change of one character.
  plants[plants.findIndex((p) => p.what === 'placeholder: set below')] = edit(CFN, '"#cloud-config",', '"#cloud-config ",', CFN, 'the embedded cloud-init drifting from the file')
  plants.push(edit(ARM, '"cloudInit": "#cloud-config\\n', '"cloudInit": "#cloud-config \\n', ARM, 'the embedded cloud-init drifting from the file'))

  let failed = 0
  for (const plant of plants) {
    let planted = false
    const tree = {
      ...real,
      read: (p) => {
        const s = real.read(p)
        if (p !== plant.file) return s
        planted = true
        return plant.apply(s)
      },
    }
    let problems
    try {
      problems = check(tree)
    } catch (e) {
      problems = [`${plant.kind}: ${e.message}`]
    }
    const hit = problems.find((p) => p.startsWith(`${plant.kind}: `))
    if (!planted || !hit) {
      failed++
      console.error(`selftest: NOT REFUSED — ${plant.file}: ${plant.what}` + (problems.length ? `\n    other problems: ${problems.join('; ')}` : ''))
    } else {
      console.log(`selftest: refused — ${plant.what}\n    ${hit}`)
    }
  }
  // The parser's own refusal is a problem of the file's kind; the facts above prove the reading.
  if (failed) {
    console.error(`selftest: ${failed} of ${plants.length} plants were not refused`)
    process.exit(1)
  }
  console.log(`selftest: ${plants.length} plants, each refused; the subset parser reads compose.yaml as the node's tests do on ${facts.length} facts`)
}

/* ------------------------------------ the YAML subset ------------------------------------ */

// Block mappings and sequences by indentation (spaces only), plain and quoted scalars, flow
// sequences of scalars, literal block scalars (| and |-), comments. Anything else is refused by
// name, so a template that needs more is noticed here and not misread.
export function parseYAML(text, where = 'yaml') {
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('\t')) throw new Error(`${where}:${i + 1}: a tab; the subset is indented with spaces`)
  }
  // The meaningful text of a line: comments cut, blank lines null. Block scalars read raw lines.
  const content = (i) => {
    const s = cutComment(lines[i])
    return s.trim() === '' ? null : s
  }
  const indentOf = (s) => s.length - s.trimStart().length
  let pos = 0
  const next = () => {
    while (pos < lines.length && content(pos) === null) pos++
    return pos < lines.length ? content(pos) : null
  }
  const KEY = /^([A-Za-z0-9_.$/-]+)\s*:(?:\s+(.*)|)$/

  function block(minIndent) {
    const first = next()
    if (first === null) return null
    const indent = indentOf(first)
    if (indent < minIndent) return null
    return first.trimStart().startsWith('- ') || first.trim() === '-' ? sequence(indent) : mapping(indent)
  }

  function mapping(indent) {
    const out = {}
    for (;;) {
      const s = next()
      if (s === null || indentOf(s) !== indent) break
      if (indentOf(s) > indent) throw new Error(`${where}:${pos + 1}: unexpected indentation`)
      const m = s.trim().match(KEY)
      if (!m) throw new Error(`${where}:${pos + 1}: not a "key: value" line in the subset: ${s.trim()}`)
      const [, key, rest] = m
      if (key in out) throw new Error(`${where}:${pos + 1}: the key ${key} twice`)
      pos++
      out[key] = value(rest, indent)
    }
    return out
  }

  function sequence(indent) {
    const out = []
    for (;;) {
      const s = next()
      if (s === null || indentOf(s) !== indent || !(s.trimStart().startsWith('- ') || s.trim() === '-')) break
      const rest = s.trim() === '-' ? '' : s.trimStart().slice(2)
      if (rest.trim() !== '' && KEY.test(rest.trim())) {
        // A mapping that starts on the dash's line: read it as if the dash were two spaces.
        lines[pos] = ' '.repeat(indent + 2) + rest
        out.push(mapping(indent + 2))
      } else {
        pos++
        out.push(value(rest, indent))
      }
    }
    return out
  }

  // The value after "key:" or "- ": nothing (a nested block, or null), a literal block, a scalar.
  function value(rest, indent) {
    const r = (rest || '').trim()
    if (r === '') {
      const s = next()
      return s !== null && indentOf(s) > indent ? block(indent + 1) : null
    }
    if (r === '|' || r === '|-') return literal(indent, r === '|-')
    if (r.startsWith('|') || r.startsWith('>') || r.startsWith('&') || r.startsWith('*') || r.startsWith('!') || r.startsWith('{')) {
      throw new Error(`${where}:${pos}: ${r[0]} is outside the subset (folded scalars, anchors, tags and flow mappings)`)
    }
    return scalar(r, pos)
  }

  function literal(indent, strip) {
    const body = []
    let blockIndent = -1
    while (pos < lines.length) {
      const raw = lines[pos]
      if (raw.trim() === '') { body.push(''); pos++; continue }
      const ind = indentOf(raw)
      if (blockIndent < 0) {
        if (ind <= indent) break
        blockIndent = ind
      }
      if (ind < blockIndent) break
      body.push(raw.slice(blockIndent))
      pos++
    }
    while (body.length && body[body.length - 1] === '') body.pop()
    return body.join('\n') + (strip ? '' : '\n')
  }

  function scalar(r, at) {
    if (r.startsWith('"')) {
      if (!r.endsWith('"') || r.length < 2) throw new Error(`${where}:${at}: an unterminated double-quoted scalar`)
      return JSON.parse(r)
    }
    if (r.startsWith("'")) {
      if (!r.endsWith("'") || r.length < 2) throw new Error(`${where}:${at}: an unterminated single-quoted scalar`)
      return r.slice(1, -1).replace(/''/g, "'")
    }
    if (r.startsWith('[')) {
      if (!r.endsWith(']')) throw new Error(`${where}:${at}: a flow sequence must end on its line`)
      const inner = r.slice(1, -1).trim()
      return inner === '' ? [] : splitFlow(inner).map((item) => scalar(item.trim(), at))
    }
    if (r === 'null' || r === '~') return null
    if (r === 'true') return true
    if (r === 'false') return false
    if (/^-?(0|[1-9][0-9]*)$/.test(r)) return Number(r)
    // A plain scalar YAML would read otherwise is refused rather than read leniently: a colon-space
    // makes it a mapping, a trailing colon a key, and an indicator at its start something else.
    if (r.includes(': ') || r.endsWith(':') || /^[@`|>&*!%{}[\],?'"-]/.test(r)) {
      throw new Error(`${where}:${at}: a plain scalar YAML reads as something else; quote it or use a literal block: ${r}`)
    }
    return r
  }

  function splitFlow(s) {
    const out = []
    let cur = ''
    let quote = null
    for (const c of s) {
      if (quote) {
        cur += c
        if (c === quote) quote = null
      } else if (c === '"' || c === "'") {
        quote = c
        cur += c
      } else if (c === ',') {
        out.push(cur)
        cur = ''
      } else cur += c
    }
    out.push(cur)
    return out
  }

  const doc = block(0)
  if (next() !== null) throw new Error(`${where}:${pos + 1}: text after the document`)
  return doc
}

// A comment starts at a # that begins the line or follows whitespace, outside quotes.
function cutComment(line) {
  let quote = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === quote) quote = null
    } else if (c === '"' || c === "'") {
      quote = c
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i).replace(/\s+$/, '')
    }
  }
  return line.replace(/\s+$/, '')
}

/* ------------------------------------ main ------------------------------------ */

const self = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (self) {
  const arg = process.argv[2]
  if (arg === '--selftest') selftest()
  else if (arg === '--sync') sync()
  else if (arg) {
    console.error('usage: node scripts/deploy-check.mjs [--selftest | --sync]')
    process.exit(2)
  } else {
    const problems = check(realTree())
    if (problems.length) {
      console.error('deploy-check: the deploy templates have drifted:\n  ' + problems.join('\n  '))
      process.exit(1)
    }
    console.log(`deploy-check: ${CLOUD_INIT}, ${CFN}, ${ARM}, ${GCP}, ${DO}, ${RENDER} and ${DOC} hold together`)
  }
}
