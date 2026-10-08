// THIRD_PARTY_NOTICES, written by `make notices` and held to its inputs by `make notices-check`.
//
// The file carries the licence text of everything the artifacts built from this repository
// redistribute, from three dependency sets as their own tools report them, classified by nobody:
//
//   1. the Go modules whose packages the shipped binary links (`go list -deps ./cmd/hdtp-gateway`,
//      under GOWORK=off so it is the released identity module and not a workspace's checkout), each
//      with the LICENSE, COPYING, UNLICENSE and NOTICE files its module directory holds;
//   2. the crates the limits sidecar builds (`cargo metadata` over cmd/hdtp-limitd/Cargo.toml: the
//      whole lock), each with its `license` field and the licence files beside its manifest or, for
//      a crate inside a larger git checkout, the nearest ones above it;
//   3. the npm packages the portal bundles into web/dist (`npm ls --omit=dev --all` in web/), each
//      with its `license` field and the licence files in its node_modules directory.
//
// The header records the sha256 of go.sum, cmd/hdtp-limitd/Cargo.lock and web/package-lock.json,
// the files that change when any of the three sets does. `--check` recomputes those and compares,
// which needs none of the tools above, so it runs on every `make check`.
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = 'THIRD_PARTY_NOTICES'
const INPUTS = ['go.sum', 'cmd/hdtp-limitd/Cargo.lock', 'web/package-lock.json']
const LICENCE_FILE = /^(licen[cs]e|copying|unlicense|notice)([.\-_].*)?$/i

const fail = (msg) => { console.error(`notices: ${msg}`); process.exit(1) }
const sha256 = (p) => createHash('sha256').update(readFileSync(join(root, p))).digest('hex')
const inputLines = () => INPUTS.map((p) => `  ${p.padEnd(28)}sha256 ${sha256(p)}`)
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, encoding: 'utf8', maxBuffer: 1 << 28, env: { ...process.env, GOWORK: 'off' } })

function check() {
  let text
  try { text = readFileSync(join(root, OUT), 'utf8') } catch { fail(`${OUT} is missing: run make notices and commit it`) }
  const stale = inputLines().filter((l) => !text.includes(`\n${l}\n`))
  if (stale.length) {
    fail(`${OUT} was not made from the dependency set on disk; its header does not carry:\n` +
      `${stale.map((l) => l.trim()).join('\n')}\nrun make notices and commit the result`)
  }
  console.log(`notices-check: ${OUT} matches ${INPUTS.join(', ')}`)
}

// Every licence-like file in dir, sorted by name; none when the directory has none or is not there.
function licenceFiles(dir) {
  let names
  try { names = readdirSync(dir) } catch { return [] }
  return names.filter((n) => LICENCE_FILE.test(n)).sort().map((n) => ({ name: n, text: readFileSync(join(dir, n), 'utf8') }))
}

// `go list -json` prints one object after another, so the stream is split at the top-level braces,
// skipping the ones inside strings.
function splitJSON(text) {
  const objs = []
  let depth = 0, start = 0, inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (inString) { if (c === '\\') i++; else if (c === '"') inString = false; continue }
    if (c === '"') inString = true
    else if (c === '{') { if (depth++ === 0) start = i }
    else if (c === '}' && --depth === 0) objs.push(JSON.parse(text.slice(start, i + 1)))
  }
  return objs
}

function goModules() {
  const mods = new Map()
  for (const p of splitJSON(run('go', ['list', '-deps', '-json=Module,Standard', './cmd/hdtp-gateway'], root))) {
    if (p.Standard || !p.Module || p.Module.Main) continue
    const m = p.Module
    const id = `${m.Path} ${m.Version}`
    if (mods.has(id)) continue
    mods.set(id, {
      id,
      note: m.Replace ? `replaced by ${m.Replace.Path} (go.mod)` : '',
      files: licenceFiles(m.Replace ? m.Replace.Dir : m.Dir),
    })
  }
  return [...mods.values()].sort(byId)
}

function crates() {
  const meta = JSON.parse(run('cargo', ['metadata', '--format-version', '1', '--locked', '--manifest-path', 'cmd/hdtp-limitd/Cargo.toml'], root))
  return meta.packages.filter((p) => p.id !== meta.resolve.root).map((p) => {
    let dir = dirname(p.manifest_path), files = licenceFiles(dir), above = ''
    for (let i = 0; i < 3 && files.length === 0; i++) { dir = dirname(dir); above += '../'; files = licenceFiles(dir) }
    const where = above ? `; licence files at ${above} from the crate` : ''
    return { id: `${p.name} ${p.version}`, note: `license: ${p.license}; source: ${p.source}${where}`, files }
  }).sort(byId)
}

function npmPackages() {
  let tree
  try { tree = JSON.parse(run('npm', ['ls', '--omit=dev', '--all', '--long', '--json'], join(root, 'web'))) }
  catch (e) { fail(`npm ls failed in web/ (run \`npm ci\` there first, as make web does):\n${e.stdout || e.message}`) }
  const pkgs = new Map()
  const walk = (deps) => {
    for (const [name, d] of Object.entries(deps || {})) {
      const id = `${name} ${d.version}`
      if (!pkgs.has(id)) pkgs.set(id, { id, note: `license: ${d.license}`, files: licenceFiles(d.path) })
      walk(d.dependencies)
    }
  }
  walk(tree.dependencies)
  return [...pkgs.values()].sort(byId)
}

function render(sections) {
  const rule = '='.repeat(80), line = '-'.repeat(80)
  const out = [
    'Third-party notices for hdtp-gateway', rule, '',
    'What the artifacts built from this repository redistribute, under the licences below: the',
    'shipped binary (the Go modules it links), the limits sidecar (the crates it builds) and the',
    'portal bundled into web/dist (the npm packages it ships). Each entry carries the licence files',
    "as the dependency's own source holds them; this file classifies nothing.", '',
    'Written by `make notices` (scripts/notices.mjs) from these inputs, which `make notices-check`',
    '(part of `make check`) holds it to:', '', ...inputLines(), '',
    'Not repeated here: the fonts under web/dist/fonts, whose SIL Open Font License texts are beside',
    'them (web/dist/fonts/OFL-*.txt); and the modification notice for the copy of frp in',
    "third_party/frp, which is NOTICE and third_party/frp.patch (frp's licence is in section 1,",
    'under github.com/fatedier/frp).', '', 'Contents',
  ]
  sections.forEach((s, i) => out.push(`  ${i + 1}. ${s.title}: ${s.entries.length}`))
  sections.forEach((s, i) => {
    out.push('', '', rule, `${i + 1}. ${s.title}`, `   ${s.how}`, rule)
    for (const e of s.entries) {
      out.push('', line, e.id, ...(e.note ? [e.note] : []), line)
      for (const f of e.files) out.push(`[${f.name}]`, f.text.replace(/\r\n/g, '\n').replace(/\s+$/, ''), '')
    }
  })
  return out.join('\n') + '\n'
}

if (process.argv.includes('--check')) {
  check()
} else {
  const sections = [
    { title: 'Go modules the shipped binary links', how: 'go list -deps ./cmd/hdtp-gateway (GOWORK=off); the licence files of each module directory', entries: goModules() },
    { title: 'Crates the limits sidecar builds', how: "cargo metadata over cmd/hdtp-limitd/Cargo.toml, the whole lock; each crate's license field and licence files", entries: crates() },
    { title: 'npm packages the portal bundles into web/dist', how: "npm ls --omit=dev --all in web/; each package's license field and licence files", entries: npmPackages() },
  ]
  const missing = sections.flatMap((s) => s.entries.filter((e) => e.files.length === 0).map((e) => `${s.title}: ${e.id}`))
  if (missing.length) fail(`no licence file found for:\n  ${missing.join('\n  ')}`)
  writeFileSync(join(root, OUT), render(sections))
  console.log(`notices: wrote ${OUT} (${sections.map((s) => `${s.entries.length} in "${s.title}"`).join(', ')})`)
}
