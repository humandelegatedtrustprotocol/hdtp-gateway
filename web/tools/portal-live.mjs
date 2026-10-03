// Feature checks against the RUNNING alice/bob containers (the real test bed):
//   node tools/portal-live.mjs [--setup-alice <url>] [--setup-bob <url>] [--media] [--tools] [--ui] <outDir>
import { launch, openNode } from './portal-login.mjs'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const argv = process.argv.slice(2)
const flag = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined }
const outDir = argv.filter(a => !a.startsWith('--') && a !== flag('--setup-alice') && a !== flag('--setup-bob')).pop() || 'qa-out'
await mkdir(outDir, { recursive: true })
const ALICE = process.env.ALICE || 'http://localhost:18120', BOB = process.env.BOB || 'http://localhost:18121'
const log = (...a) => console.log('  ' + a.join(' '))

const browser = await launch()
try {
  const a = await openNode(browser, 'alice', ALICE, flag('--setup-alice'))
  const b = await openNode(browser, 'bob', BOB, flag('--setup-bob'))
  const ca = await a.get('/api/conversations'), cb = await b.get('/api/conversations')
  const bOnA = (ca.contacts || [])[0], aOnB = (cb.contacts || [])[0]
  log(`alice's contacts: ${(ca.contacts || []).map(c => c.label).join(', ') || '(none)'} · bob's: ${(cb.contacts || []).map(c => c.label).join(', ') || '(none)'}`)
  if (!bOnA || !aOnB) { log('the two are not paired; pair them in the portal first'); process.exit(1) }

  if (argv.includes('--tools')) {
    const tl = await a.get('/api/contacts/' + encodeURIComponent(bOnA.fingerprint) + '/tools')
    log(`what alice can call on bob (through the tunnel): ${(tl.tools || []).map(t => t.name).join(', ') || tl.error}`)
    const au = await a.get('/api/audit')
    // Newest first: slice(-1) used to take the OLDEST row here and reported a
    // long-dead failure as if it were this run's.
    const last = (au.rows || []).filter(r => r.Action === 'list_contact_tools')[0]
    log(`audit says the list came: ${last ? last.Outcome : '(no row)'}`)
  }
  if (argv.includes('--media')) {
    const d = await a.get('/api/conversations?contact=' + encodeURIComponent(bOnA.fingerprint))
    const up = await a.page.evaluate(async ({ fpr, msgId }) => {
      const csrf = (document.cookie.split('; ').find(c => c.startsWith('hdtp_csrf')) || '').split('=').slice(1).join('=')
      const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(120).fill(3)])
      const fd = new FormData(); fd.append('file', new Blob([png], { type: 'image/png' }), 'qa.png')
      fd.append('contact', fpr); fd.append('msg_id', msgId); fd.append('csrf', csrf); fd.append('account', localStorage.getItem('hdtp.account') || '')
      const r = await fetch('/messages/send_media', { method: 'POST', headers: { 'X-HDTP-Csrf': csrf }, body: fd })
      return { status: r.status, body: (await r.text()).slice(0, 160) }
    }, { fpr: bOnA.fingerprint, msgId: d.new_msg_id })
    log(`media alice→bob: ${up.status} ${up.body}`)
    await new Promise(r => setTimeout(r, 2500))
    const cb2 = await b.get('/api/conversations?contact=' + encodeURIComponent(aOnB.fingerprint))
    const m = (cb2.messages || []).filter(x => x.media).slice(-1)[0]
    log(`bob's newest media: ${m ? `${m.media.filename} ${m.media.mime} held=${Boolean(m.media.hash)}` : '(none)'}`)
  }
  if (argv.includes('--ui')) {
    await a.page.goto(ALICE + '/messages?contact=' + encodeURIComponent(bOnA.fingerprint), { waitUntil: 'load' })
    await a.page.waitForSelector('.composer', { timeout: 15000 }); await new Promise(r => setTimeout(r, 1500))
    await a.page.screenshot({ path: resolve(outDir, 'alice-inbox.png') })
    const plus = await a.page.$('button[aria-label="Add"]')
    if (plus) { await plus.click(); await a.page.waitForFunction(() => document.querySelector('.plusmenu .tile') || !/Asking/.test(document.querySelector('.plusmenu .plus-empty')?.textContent || ''), { timeout: 20000 }).catch(() => {}); log(`+ tiles: ${(await a.page.$$eval('.plusmenu .tile', els => els.map(e => e.textContent.trim()))).join(', ') || '(empty)'}`); await a.page.screenshot({ path: resolve(outDir, 'alice-plus.png') }) }
    log(`shots in ${outDir}`)
  }
  await a.ctx.close(); await b.ctx.close()
} finally { await browser.close() }
