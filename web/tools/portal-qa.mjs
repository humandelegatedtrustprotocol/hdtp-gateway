// Headless portal QA against two locally running nodes.
//   node tools/portal-qa.mjs http://localhost:19080 http://localhost:19081 <outDir> [--pair]
// Registers a virtual passkey on each node (Chrome's own WebAuthn via CDP, as the
// harness does), optionally pairs them (invite on A → accept on B → approve on A)
// and exchanges messages, then screenshots every portal view on A at desktop and
// mobile widths. Dev-only; nothing here ships.
import puppeteer from 'puppeteer-core'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const [A, B, outDir, ...flags] = process.argv.slice(2)
if (!A || !B || !outDir) { console.error('usage: node tools/portal-qa.mjs <nodeA> <nodeB> <outDir> [--pair]'); process.exit(2) }
const PAIR = flags.includes('--pair')
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
await mkdir(outDir, { recursive: true })

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--ignore-certificate-errors'] })
const log = (...a) => console.log('  ' + a.join(' '))

async function open (base) {
  const ctx = await browser.createBrowserContext()
  const page = await ctx.newPage()
  await page.setViewport({ width: 1440, height: 900 })
  page.on('pageerror', e => log(`[pageerror ${base}] ${String(e).slice(0, 160)}`))
  page.on('console', m => { if (m.type() === 'error') log(`[console ${base}] ${m.text().slice(0, 160)}`) })
  const cdp = await page.createCDPSession()
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  return { ctx, page, base }
}

async function setup (n, tag) {
  await n.page.goto(n.base + '/setup', { waitUntil: 'load' })
  await n.page.waitForSelector('#go', { timeout: 15000 })
  await n.page.$eval('#tag', (el, v) => { el.value = ''; }, tag)
  await n.page.type('#tag', tag)
  // The wizard navigates to / on success; an evaluate racing that navigation throws
  // "execution context destroyed", so wait for the navigation itself and treat the
  // race as success.
  const nav = n.page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {})
  await n.page.click('#go')
  await nav
  await n.page.goto(n.base + '/', { waitUntil: 'load' })
  const s = await n.page.evaluate(() => fetch('/api/session', { headers: { Accept: 'application/json' } }).then(r => r.json()))
  log(`${n.base}: signed_in=${s.signed_in} accounts=${s.accounts.length}`)
  return s
}

// The write endpoints take the same form the views post: csrf + account in the body.
async function post (n, path, fields) {
  return n.page.evaluate(async ({ path, fields }) => {
    const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
    const account = localStorage.getItem('pact.account') || ''
    const body = new URLSearchParams({ csrf, account, ...fields })
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Pact-Csrf': csrf }, body: body.toString() })
    return { ok: r.ok, url: r.url, status: r.status }
  }, { path, fields })
}
async function get (n, path) {
  return n.page.evaluate(async (path) => {
    const account = localStorage.getItem('pact.account') || ''
    const r = await fetch(path + (path.includes('?') ? '&' : '?') + 'account=' + encodeURIComponent(account), { headers: { Accept: 'application/json' } })
    return r.json()
  }, path)
}

async function shot (n, path, name, opts = {}) {
  const { width = 1440, height = 900, full = true, dark = false } = opts
  await n.page.setViewport({ width, height, isMobile: width < 700, deviceScaleFactor: 1 })
  await n.page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }])
  await n.page.goto(n.base + path, { waitUntil: 'load' })
  await n.page.waitForSelector('main', { timeout: 15000 }).catch(() => {})
  await n.page.evaluate(() => document.fonts.ready)
  await new Promise(r => setTimeout(r, 700)) // data fetches + fonts settle; SSE never goes idle
  const file = resolve(outDir, name + '.png')
  await n.page.screenshot({ path: file, fullPage: full })
  log(`shot ${name}`)
}

try {
  const a = await open(A), b = await open(B)
  await setup(a, 'qa-a'); await setup(b, 'qa-b')
  // A fresh node has no identity; the public surface serves nothing until one exists.
  for (const [n, slug, name] of [[a, 'alice', 'Alice Rao'], [b, 'bob', 'Bob Nair']]) {
    const r = await post(n, '/identity/create', { slug, name, algo: process.env.ALGO || 'p256' })
    log(`create → ${new URL(r.url).search || 'ok'}`)
    await n.page.goto(n.base + '/', { waitUntil: 'load' })
    const s = await get(n, '/api/session')
    log(`${n.base}: identity ${slug} created ok=${r.ok}; accounts=${s.accounts.length}`)
  }

  if (PAIR) {
    // Invite on A (manual approval, so the requests flow is exercised too).
    const inv = await post(a, '/invites/create', { label: 'QA pairing', max_uses: '1', preset: 'basic' })
    const token = new URL(inv.url).searchParams.get('new')
    const invites = await get(a, '/api/invites')
    const link = `${invites.public_url}/i/${token}`
    log(`invite: ${link}`)
    // Accept on B.
    const acc = await post(b, '/contacts/add', { invite_url: link, grant: 'basic' })
    log(`accept on B: ok=${acc.ok} → ${new URL(acc.url).search}`)
    // Approve on A.
    await new Promise(r => setTimeout(r, 1500))
    const reqs = await get(a, '/api/requests')
    const pend = (reqs.pending || [])[0]
    log(`pending on A: ${(reqs.pending || []).length}`)
    if (pend) {
      const ap = await post(a, `/requests/${encodeURIComponent(pend.fingerprint)}/approve`, { preset: 'basic' })
      log(`approve: ok=${ap.ok} → ${new URL(ap.url).search}`)
      const cd = await get(a, '/api/contacts/' + encodeURIComponent(pend.fingerprint))
      log(`B on A: status=${cd.status} preset=${cd.preset} perms=${(cd.permissions || []).filter(p => p.on).map(p => p.name).join(',') || '(none)'}`)
    }
    await new Promise(r => setTimeout(r, 1500))
    // Messages both ways.
    const ca = await get(a, '/api/conversations'), cb = await get(b, '/api/conversations')
    const bOnA = (ca.contacts || [])[0], aOnB = (cb.contacts || [])[0]
    log(`contacts: A sees ${(ca.contacts || []).length}, B sees ${(cb.contacts || []).length}`)
    const say = async (n, fpr, text) => {
      const d = await get(n, '/api/conversations?contact=' + encodeURIComponent(fpr))
      const r = await post(n, '/messages/send', { contact: fpr, text, msg_id: d.new_msg_id })
      log(`send from ${n.base}: ok=${r.ok} ${new URL(r.url).search}`)
      await new Promise(r => setTimeout(r, 800))
    }
    if (bOnA && aOnB) {
      await say(a, bOnA.fingerprint, 'Hi — are you free Thursday evening?')
      await say(b, aOnB.fingerprint, 'Thursday after 19:00 works. Kappo at 19:30?')
      await say(a, bOnA.fingerprint, 'Perfect, book it and send the invite.')
      await say(b, aOnB.fingerprint, 'Booked. Calendar invite is on its way.')
    }
    await new Promise(r => setTimeout(r, 1000))
    const conv = await get(a, '/api/conversations?contact=' + encodeURIComponent(bOnA?.fingerprint || ''))
    log(`A thread has ${(conv.messages || []).length} messages`)
    const au = await get(a, '/api/audit')
    for (const r of (au.rows || []).slice(0, 10)) log(`  audit A: ${r.ActorKind}/${String(r.ActorID).slice(0, 24)} ${r.Action} → ${r.Outcome}`)
    const aub = await get(b, '/api/audit')
    for (const r of (aub.rows || []).slice(0, 6)) log(`  audit B: ${r.ActorKind}/${String(r.ActorID).slice(0, 24)} ${r.Action} → ${r.Outcome}`)
    const bc = await get(b, '/api/contacts/' + encodeURIComponent(aOnB.fingerprint))
    log(`A on B: status=${bc.status} perms=${(bc.permissions || []).filter(p => p.on).map(p => p.name).join(',')} theirs=${(bc.their_permissions || []).join(',') || '(none)'}`)
    globalThis.__fprB = bOnA?.fingerprint

    // Bob widens what Alice may do on his node: files and calendar tools. `basic`
    // is text only, so without this a media send is (correctly) refused and no
    // tool beyond the protocol's plumbing is listed.
    if ((flags.includes('--media') || flags.includes('--tools')) && aOnB) {
      const r = await b.page.evaluate(async ({ fpr }) => {
        const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
        const body = new URLSearchParams({ csrf, account: localStorage.getItem('pact.account') || '', preset: 'basic' })
        for (const p of ['message.text', 'message.media', 'calendar.availability', 'calendar.book', 'status.view']) body.append('perm', p)
        const res = await fetch('/contacts/' + encodeURIComponent(fpr) + '/permissions', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Pact-Csrf': csrf }, body: body.toString() })
        return res.status
      }, { fpr: aOnB.fingerprint })
      log(`B grants A media + calendar: ${r}`)
      await new Promise(r => setTimeout(r, 800))
    }

    // --media: a file from A's composer must arrive on B as a media message held locally.
    if (flags.includes('--media') && bOnA && aOnB) {
      const d = await get(a, '/api/conversations?contact=' + encodeURIComponent(bOnA.fingerprint))
      const up = await a.page.evaluate(async ({ fpr, msgId }) => {
        const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
        const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(200).fill(7)])
        const fd = new FormData()
        fd.append('file', new Blob([png], { type: 'image/png' }), 'hello.png')
        fd.append('contact', fpr); fd.append('msg_id', msgId); fd.append('csrf', csrf); fd.append('account', localStorage.getItem('pact.account') || '')
        const r = await fetch('/messages/send_media', { method: 'POST', headers: { 'X-Pact-Csrf': csrf }, body: fd })
        return { status: r.status, body: await r.text() }
      }, { fpr: bOnA.fingerprint, msgId: d.new_msg_id })
      log(`media upload A→B: ${up.status} ${up.body.slice(0, 100)}`)
      await new Promise(r => setTimeout(r, 1200))
      const cb2 = await get(b, '/api/conversations?contact=' + encodeURIComponent(aOnB.fingerprint))
      const media = (cb2.messages || []).filter(m => m.media)
      log(`B sees media: ${media.length} (${media.map(m => `${m.media.filename} ${m.media.mime} hash=${m.media.hash ? 'yes' : 'no'}`).join('; ')})`)
      const ca2 = await get(a, '/api/conversations?contact=' + encodeURIComponent(bOnA.fingerprint))
      const mine = (ca2.messages || []).filter(m => m.media && m.mine)
      log(`A sees own media: ${mine.length}${mine[0]?.bad ? ' bad=' + mine[0].bad : ''}`)
    }

    // --tools: what B lets A call, and one call through the portal endpoint.
    if (flags.includes('--tools') && bOnA) {
      const tl = await get(a, '/api/contacts/' + encodeURIComponent(bOnA.fingerprint) + '/tools')
      log(`B's tools for A: ${(tl.tools || []).map(t => t.name).join(', ') || tl.error}`)
      const r = await a.page.evaluate(async ({ fpr }) => {
        const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
        const body = new URLSearchParams({ csrf, account: localStorage.getItem('pact.account') || '', tool: 'get_card', args: '{}' })
        const res = await fetch('/contacts/' + encodeURIComponent(fpr) + '/call', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Pact-Csrf': csrf }, body: body.toString() })
        return { status: res.status, body: await res.text() }
      }, { fpr: bOnA.fingerprint })
      log(`call get_card on B: ${r.status} → ${r.body.includes('BEGIN:VCARD') ? 'card returned' : r.body.slice(0, 120)}`)
    }
  }

  const fpr = globalThis.__fprB
  // --ui: the composer's tool drawer and the collapsible panel, as a person sees them.
  if (flags.includes('--ui') && fpr) {
    await a.page.setViewport({ width: 1440, height: 900 })
    await a.page.goto(A + '/messages?contact=' + encodeURIComponent(fpr), { waitUntil: 'load' })
    await a.page.waitForSelector('.composer', { timeout: 15000 })
    await new Promise(r => setTimeout(r, 1500))
    const plus = await a.page.$('button[aria-label="Add"]')
    log(`+ button present: ${Boolean(plus)}`)
    if (plus) {
      await plus.click(); await new Promise(r => setTimeout(r, 500))
      const tiles = await a.page.$$eval('.plusmenu .tile', els => els.map(e => e.textContent.trim()))
      log(`+ menu tiles: ${tiles.join(', ') || '(empty)'}`)
      const style = await a.page.evaluate(() => {
        const c = document.querySelector('.plusmenu .tile .circ'); const t = document.querySelector('.plusmenu .tile'); const m = document.querySelector('.plusmenu')
        const g = (el) => { const s = getComputedStyle(el); return { w: s.width, h: s.height, d: s.display, r: s.borderRadius, fd: s.flexDirection } }
        return { circ: g(c), tile: g(t), menu: { cols: getComputedStyle(m).gridTemplateColumns, d: getComputedStyle(m).display } }
      })
      log(`+ menu styles: ${JSON.stringify(style)}`)
      await a.page.screenshot({ path: resolve(outDir, 'inbox-plus-menu.png') })
      const tool = await a.page.$('.plusmenu .tile[title="check_availability"]')
      if (tool) { await tool.click(); await new Promise(r => setTimeout(r, 500)); await a.page.screenshot({ path: resolve(outDir, 'inbox-tools-form.png') }); log('shot inbox-plus-menu, inbox-tools-form') }
      await a.page.click('.tooldock-h button[aria-label="Close tools"]').catch(() => {})
    }
    const details = await a.page.$('.thread-h .details')
    if (details) { await details.click(); await new Promise(r => setTimeout(r, 400)); await a.page.screenshot({ path: resolve(outDir, 'inbox-panel-off.png') }); log('shot inbox-panel-off'); await details.click() }
    const rail = await a.page.$('.rail-btn')
    if (rail) { await rail.click(); await new Promise(r => setTimeout(r, 400)); await a.page.screenshot({ path: resolve(outDir, 'inbox-rail.png') }); log('shot inbox-rail'); await rail.click() }
    const expand = await a.page.$('.thread-h .expand')
    if (expand) { await expand.click(); await new Promise(r => setTimeout(r, 400)); await a.page.screenshot({ path: resolve(outDir, 'inbox-focus.png') }); log('shot inbox-focus'); await expand.click() }
  }
  const views = ['/', '/messages' + (fpr ? '?contact=' + encodeURIComponent(fpr) : ''), '/contacts', '/requests', '/invites', '/card', '/integrations', '/identity', '/owners', '/settings', '/audit']
  if (fpr) views.push('/contacts/' + encodeURIComponent(fpr))
  for (const v of views) {
    const name = (v.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '') || 'home')
    await shot(a, v, name + '-desktop', { full: !v.startsWith('/messages') })
  }
  await shot(a, views[1], 'messages-mobile', { width: 390, height: 844, full: false })
  await shot(a, '/', 'home-mobile', { width: 390, height: 844, full: true })
  await shot(a, views[1], 'messages-dark', { dark: true, full: false })
  // The sign-in page, from a context without a session.
  const fresh = await open(A)
  await shot(fresh, '/login', 'login-desktop', { full: false })
  await fresh.ctx.close()
  await a.ctx.close(); await b.ctx.close()
} finally {
  await browser.close()
}
