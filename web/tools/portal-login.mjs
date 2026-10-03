// Sign a headless browser into a RUNNING node without the owner's passkey.
//
// First run per node: pass a one-time setup link (from `hdtp-gateway passkey
// reset-wizard` inside the container); a virtual authenticator registers a passkey
// named "claude-qa" and its credential is saved under tools/.qa/ (gitignored).
// Later runs: the credential is re-added to a fresh virtual authenticator and the
// ordinary passkey sign-in is used. The owner can remove "claude-qa" on the Owners
// page at any time.
import puppeteer from 'puppeteer-core'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const QA_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '.qa')
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

export async function launch () {
  return puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--ignore-certificate-errors'] })
}

// openNode returns { ctx, page, base, post, get } signed in as the QA passkey.
export async function openNode (browser, name, base, setupURL) {
  const ctx = await browser.createBrowserContext()
  const page = await ctx.newPage()
  await page.setViewport({ width: 1440, height: 900 })
  page.on('pageerror', e => console.log(`  [pageerror ${name}] ${String(e).slice(0, 160)}`))
  const cdp = await page.createCDPSession()
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  const credFile = resolve(QA_DIR, name + '.json')
  let cred = null
  try { cred = JSON.parse(await readFile(credFile, 'utf8')) } catch {}

  if (cred) {
    // Registered as non-discoverable; sign-in is the discoverable flow, so re-add it resident.
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: { ...cred, isResidentCredential: true } })
    await page.goto(base + '/login', { waitUntil: 'load' })
    await page.waitForSelector('main button', { timeout: 15000 })
    const nav = page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {})
    await page.click('main button')
    await nav
  } else {
    if (!setupURL) throw new Error(`${name}: no saved credential and no setup link — run \`docker exec hdtpcf-${name} /hdtp-gateway passkey reset-wizard\` and pass the URL`)
    const u = new URL(setupURL); const b = new URL(base); u.protocol = b.protocol; u.host = b.host
    await page.goto(u.toString(), { waitUntil: 'load' })
    await page.waitForSelector('#go', { timeout: 15000 })
    await page.$eval('#tag', el => { el.value = '' })
    await page.type('#tag', 'claude-qa')
    const nav = page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {})
    await page.click('#go')
    await nav
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
    if (credentials.length !== 1) throw new Error(`${name}: expected one registered credential, got ${credentials.length}`)
    await mkdir(QA_DIR, { recursive: true })
    await writeFile(credFile, JSON.stringify(credentials[0]), { mode: 0o600 })
    console.log(`  ${name}: registered passkey "claude-qa"; credential saved to ${credFile}`)
  }
  await page.goto(base + '/', { waitUntil: 'load' })
  const s = await page.evaluate(() => fetch('/api/session', { headers: { Accept: 'application/json' } }).then(r => r.json()))
  if (!s.signed_in) throw new Error(`${name}: sign-in failed`)
  console.log(`  ${name}: signed in, ${s.accounts.length} identit${s.accounts.length === 1 ? 'y' : 'ies'}: ${s.accounts.map(a => a.slug).join(', ')}`)

  const post = (path, fields) => page.evaluate(async ({ path, fields }) => {
    const csrf = (document.cookie.split('; ').find(c => c.startsWith('hdtp_csrf')) || '').split('=').slice(1).join('=')
    const body = new URLSearchParams({ csrf, account: localStorage.getItem('hdtp.account') || '', ...fields })
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-HDTP-Csrf': csrf }, body: body.toString() })
    return { ok: r.ok, status: r.status, url: r.url, body: (await r.text()).slice(0, 400) }
  }, { path, fields })
  const get = (path) => page.evaluate(async (path) => {
    const account = localStorage.getItem('hdtp.account') || ''
    const r = await fetch(path + (path.includes('?') ? '&' : '?') + 'account=' + encodeURIComponent(account), { headers: { Accept: 'application/json' } })
    return r.json()
  }, path)
  return { ctx, page, base, name, post, get, session: s }
}
