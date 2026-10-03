// The brand from hdtp-web-kit, vendored into an APP the way the sites vendor it: by release, every file
// checked against the release's manifest, pinned in kit/kit.lock. The same file serves the node's portal
// (web/) and BatonDeck's (portal/, copied by gateway/scripts/harvest.sh); it works on the directory
// above its own.
//
//   node tools/kit.mjs fetch <x.y.z>   download the release with gh, check it against its manifest, vendor it
//   node tools/kit.mjs check           THE GATE, hermetic: the vendored bytes, the lock, the manifest, the tokens
//
// An app takes the brand files and the design system's stylesheet, and nothing else: analytics.js,
// mixpanel and waitlist.js are the marketing sites', not an app's.
//
//   kit/brand/*, kit/fonts/*  ->  public/brand/, public/fonts/   served (the paths the apps always had)
//   kit/styles.css            ->  kit/styles.css                 NOT served: its classes (.card, .btn, .side,
//                                                                .msg, .sw, ...) would collide with the app's.
//                                                                It is the authority the app's tokens and
//                                                                motion are held to, below.
//   manifest.json             ->  kit/manifest.json              the release's own, verbatim
//
// `check` then holds src/brand.css — the app's palette, type and motion — to that stylesheet: every token
// the two share has the kit's value, the dark palette is drawn from the kit's own on-dark colours, the
// keyframes are the kit's, and the contrast rules of hdtp-web-kit's test/contrast.test.mjs hold in both
// themes and for the app's own pairs.
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

export const APP = join(dirname(fileURLToPath(import.meta.url)), '..')
export const REPO = 'humandelegatedtrustprotocol/hdtp-web-kit'
/** Release path prefix -> where it lands in the app. A release file matching none is not vendored. */
export const TAKE = [
  ['kit/brand/', 'public/brand/'],
  ['kit/fonts/', 'public/fonts/'],
  ['kit/styles.css', 'kit/styles.css'],
]
const LOCK = join(APP, 'kit/kit.lock')
const MANIFEST = join(APP, 'kit/manifest.json')

const sha256 = (b) => createHash('sha256').update(b).digest('hex')
const destOf = (path) => {
  for (const [from, to] of TAKE) if (path === from || (from.endsWith('/') && path.startsWith(from))) return to + path.slice(from.length)
  return null
}
function walk(dir, base = dir) {
  if (!existsSync(dir)) return []
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? walk(p, base) : [relative(base, p)]
  })
}

// ---------------------------------------------------------------- fetch

function fetchRelease(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version || '')) throw new Error('usage: kit.mjs fetch <x.y.z>')
  const tmp = mkdtempSync(join(tmpdir(), 'hdtp-web-kit-'))
  try {
    execFileSync('gh', ['release', 'download', `v${version}`, '-R', REPO, '-D', tmp, '-p', `hdtp-web-kit-${version}.tar.gz`, '-p', 'manifest.json'], { stdio: 'inherit' })
    const rawManifest = readFileSync(join(tmp, 'manifest.json'))
    const manifest = JSON.parse(rawManifest)
    if (manifest.version !== version) throw new Error(`the manifest is for ${manifest.version}, not ${version}`)
    const root = join(tmp, 'x'); mkdirSync(root)
    execFileSync('tar', ['-xzf', join(tmp, `hdtp-web-kit-${version}.tar.gz`), '-C', root])
    // The whole unpacked release must be the manifest, byte for byte, before any of it is taken.
    const have = Object.fromEntries(['kit', 'bin'].flatMap((d) => walk(join(root, d)).map((f) => [`${d}/${f}`, sha256(readFileSync(join(root, d, f)))])))
    if (JSON.stringify(Object.entries(have).sort()) !== JSON.stringify(Object.entries(manifest.files).sort())) {
      throw new Error('the unpacked release does not match its manifest; nothing was vendored')
    }
    for (const [, to] of TAKE) rmSync(join(APP, to), { recursive: true, force: true })
    const files = {}
    for (const [path, hash] of Object.entries(manifest.files).sort()) {
      const to = destOf(path)
      if (!to) continue
      mkdirSync(dirname(join(APP, to)), { recursive: true })
      cpSync(join(root, path), join(APP, to))
      files[path] = { to, sha256: hash }
    }
    mkdirSync(dirname(LOCK), { recursive: true })
    writeFileSync(MANIFEST, rawManifest)
    writeFileSync(LOCK, JSON.stringify({ version, manifest_sha256: sha256(rawManifest), files }, null, 2) + '\n')
    console.log(`hdtp-web-kit ${version}: ${Object.keys(files).length} files vendored, pinned in kit/kit.lock`)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------- the lock

/** Every way the vendored copy can differ from the pinned release. Empty is a match. */
export function lockProblems(app = APP) {
  const out = []
  const lockPath = join(app, 'kit/kit.lock'), manPath = join(app, 'kit/manifest.json')
  if (!existsSync(lockPath) || !existsSync(manPath)) return ['kit/kit.lock or kit/manifest.json is missing: run `node tools/kit.mjs fetch <x.y.z>`']
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'))
  const rawManifest = readFileSync(manPath)
  const manifest = JSON.parse(rawManifest)
  if (sha256(rawManifest) !== lock.manifest_sha256) out.push('kit/manifest.json is not the manifest the lock pinned')
  if (manifest.version !== lock.version) out.push(`the manifest is ${manifest.version}, the lock ${lock.version}`)
  // Every release file under a taken path is vendored — the whole brand set, not a pick of it.
  const want = Object.keys(manifest.files).filter((p) => destOf(p)).sort()
  const got = Object.keys(lock.files).sort()
  if (JSON.stringify(want) !== JSON.stringify(got)) out.push(`the lock lists ${got.length} files, the release has ${want.length} under the taken paths`)
  const vendored = new Set()
  for (const [path, { to, sha256: hash }] of Object.entries(lock.files)) {
    if (manifest.files[path] !== hash) out.push(`${path}: the lock's hash is not the manifest's`)
    if (destOf(path) !== to) out.push(`${path}: locked at ${to}, belongs at ${destOf(path)}`)
    const p = join(app, to)
    if (!existsSync(p)) { out.push(`${to} is missing`); continue }
    if (sha256(readFileSync(p)) !== hash) out.push(`${to} differs from hdtp-web-kit ${lock.version}'s ${path}`)
    vendored.add(to)
  }
  // Nothing else in the vendored directories: a stray file there would be served as if it were the kit's.
  for (const dir of ['public/brand', 'public/fonts', 'kit']) {
    for (const f of walk(join(app, dir))) {
      const rel = `${dir}/${f}`
      if (!vendored.has(rel) && rel !== 'kit/kit.lock' && rel !== 'kit/manifest.json') out.push(`${rel} is in a vendored directory but not in the lock`)
    }
  }
  return out
}

// ---------------------------------------------------------------- tokens

/** `--name: value` pairs of the first block matching `selector{…}`, values trimmed. */
export function tokensOf(css, block) {
  const m = css.match(block)
  if (!m) return null
  return Object.fromEntries([...m[1].matchAll(/--([\w-]+)\s*:\s*([^;]+)/g)].map((t) => [t[1], t[2].trim()]))
}
const LIGHT_BLOCK = /\/\* palette:light \*\/\s*:root\s*\{([^}]*)\}/
const DARK_BLOCK = /\/\* palette:dark \*\/\s*@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}/

function lum(hex) {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
}
export function ratio(a, b) {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}
const HEX = /^#[0-9A-Fa-f]{6}$/

/** The tokens an app shares with the kit, by name: each must carry the kit's value in the light palette. */
export const SHARED = ['bg', 'bg-2', 'bg-3', 'ink', 'ink-2', 'text', 'muted', 'faint', 'line', 'line-2',
  'accent', 'accent-2', 'accent-soft', 'accent-ink', 'accent-ui', 'accent-rgb', 'glow-rgb', 'amber', 'amber-soft',
  'sans', 'mono', 'display', 'ease-out']
/** The dark palette is the kit's on-dark set, not a second brand: app dark token -> the kit token it must equal. */
export const DARK_FROM_KIT = { bg: 'ink', 'bg-2': 'dark-panel', 'bg-3': 'ink-2', text: 'dark-text', muted: 'dark-muted', 'accent-ink': 'accent-2', ink: 'bg-3', accent: 'accent', 'accent-ui': 'accent', red: 'err-on-ink' }

/** Every way the app's brand layer departs from the kit, or breaks a contrast rule. Empty is a pass. */
export function brandProblems(app = APP) {
  const out = []
  const kitCss = readFileSync(join(app, 'kit/styles.css'), 'utf8')
  const kit = Object.fromEntries([...kitCss.matchAll(/:root\{([^}]*)\}/g)].flatMap((m) => Object.entries(tokensOf(`:root{${m[1]}}`, /:root\{([^}]*)\}/))))
  const brandCss = readFileSync(join(app, 'src/brand.css'), 'utf8')
  const light = tokensOf(brandCss, LIGHT_BLOCK)
  const darkOwn = tokensOf(brandCss, DARK_BLOCK)
  if (!light) return ['src/brand.css has no `/* palette:light */ :root{…}` block']
  if (!darkOwn) return ['src/brand.css has no `/* palette:dark */ @media (prefers-color-scheme: dark){:root{…}}` block']
  const dark = { ...light, ...darkOwn }

  for (const t of SHARED) {
    if (kit[t] === undefined) out.push(`--${t} is not a token of the kit any more`)
    else if (light[t] !== kit[t]) out.push(`--${t} is ${light[t]} in src/brand.css, ${kit[t]} in hdtp-web-kit`)
  }
  for (const [t, k] of Object.entries(DARK_FROM_KIT)) {
    if (darkOwn[t] !== kit[k]) out.push(`dark --${t} is ${darkOwn[t]}; the kit's on-dark colour for it is --${k} ${kit[k]}`)
  }
  for (const k of ['rise']) {
    const re = new RegExp(`@keyframes ${k}\\{[^\\n]*\\}\\}`)
    const a = kitCss.match(re)?.[0], b = brandCss.match(re)?.[0]
    if (!a || a !== b) out.push(`@keyframes ${k} is not the kit's`)
  }

  // Contrast, WCAG 2.2 — the kit's rules (4.5 : 1 for text, 3 : 1 for state), in each theme.
  const TEXT = ['ink', 'text', 'muted', 'faint', 'accent-ink']
  const GROUND = ['bg', 'bg-2', 'bg-3', 'accent-soft', 'raise']
  for (const [theme, tk] of [['light', light], ['dark', dark]]) {
    const v = (t) => { const x = tk[t]; const r = x && x.match(/^var\(--([\w-]+)\)$/); return r ? v(r[1]) : x }
    const need = (fg, bg, min, why) => {
      const a = v(fg), b = v(bg)
      if (!HEX.test(a || '') || !HEX.test(b || '')) { out.push(`${theme}: --${fg} or --${bg} is not a #rrggbb colour (${a}, ${b})`); return }
      const r = ratio(a, b)
      if (r < min) out.push(`${theme}: --${fg} ${a} on --${bg} ${b} is ${r.toFixed(2)} : 1, needs ${min}${why ? ` (${why})` : ''}`)
    }
    for (const fg of TEXT) for (const bg of GROUND) need(fg, bg, 4.5)
    for (const bg of ['bg', 'bg-2', 'bg-3']) need('accent-ui', bg, 3, 'focus rings, switches')
    need('amber', 'amber-soft', 4.5); need('amber', 'bg', 4.5)
    need('red', 'red-soft', 4.5); need('red', 'bg', 4.5)
    for (const fill of ['red', 'amber', 'accent-ink']) need('on-fill', fill, 4.5, 'a count or a danger button')
    need('bg', 'ink', 4.5, 'a primary button, an own message')
    need('accent-on-ink', 'ink', 4.5, 'a link inside an own message')
    for (const g of ['emergency', 'emergency-hover']) {
      need('on-emergency', g, 4.5, 'the emergency button\'s words'); need('sign-warn', g, 3, 'its warning sign')
    }
    for (const g of ['bg', 'bg-2', 'bg-3', 'raise']) need('emergency-ring', g, 3, 'the emergency button\'s edge')
    if (ratio(v('accent'), v('bg')) >= 4.5 && theme === 'light') out.push('the brand orange passes as text now; the kit says it never carries text')
  }

  // The orange never carries text, in any of the app's stylesheets.
  for (const f of ['src/brand.css', 'src/style.css', 'src/cloud.css']) {
    if (!existsSync(join(app, f))) continue
    for (const m of readFileSync(join(app, f), 'utf8').matchAll(/(?:^|[;{\s])color:\s*var\(--accent\)/g)) out.push(`${f}: --accent used as a text colour: ${m[0].trim()}`)
  }
  // An avatar's initials are text: white on each of its fills.
  const ui = existsSync(join(app, 'src/ui.tsx')) ? readFileSync(join(app, 'src/ui.tsx'), 'utf8') : ''
  const palette = ui.match(/const PALETTE = \[([^\]]*)\]/)
  if (!palette) out.push('src/ui.tsx has no PALETTE for avatars')
  else for (const h of palette[1].match(/#[0-9A-Fa-f]{6}/g) || []) if (ratio('#FFFFFF', h) < 4.5) out.push(`avatar fill ${h}: white initials are ${ratio('#FFFFFF', h).toFixed(2)} : 1`)
  return out
}

// ---------------------------------------------------------------- main

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, arg] = process.argv.slice(2)
  try {
    if (cmd === 'fetch') fetchRelease(arg)
    else if (cmd === 'check') {
      const problems = [...lockProblems(), ...brandProblems()]
      if (problems.length) {
        console.error(`kit: ${problems.length} problem(s)\n  ` + problems.join('\n  '))
        process.exit(1)
      }
      const lock = JSON.parse(readFileSync(LOCK, 'utf8'))
      console.log(`kit: hdtp-web-kit ${lock.version}, ${Object.keys(lock.files).length} files match the release; the brand holds to it in both themes`)
    } else {
      console.error('usage: kit.mjs fetch <x.y.z> | kit.mjs check'); process.exit(2)
    }
  } catch (e) {
    console.error(`kit: ${e.message}`); process.exit(1)
  }
}
