// On alice: click "Connect & authorize" on the first OAuth integration row and
// report where the browser lands (expected: the provider's sign-in page).
import { launch, openNode } from './portal-login.mjs'
const browser = await launch()
try {
  const a = await openNode(browser, 'alice', process.env.ALICE || 'http://localhost:18120')
  const errors = []
  a.page.on('console', m => { if (m.type() === 'error') errors.push(m.text().slice(0, 160)) })
  await a.page.goto(a.base + '/integrations', { waitUntil: 'load' })
  await a.page.waitForSelector('main', { timeout: 15000 }); await new Promise(r => setTimeout(r, 800))
  const rows = await a.page.$$eval('main h3, main .rowline', els => els.map(e => e.textContent.trim().slice(0, 60)))
  console.log('  rows: ' + rows.filter(Boolean).slice(0, 6).join(' | '))
  const btn = (await a.page.$$('button')).filter(async () => true)
  let target = null
  for (const b of btn) { const t = (await (await b.getProperty('textContent')).jsonValue()).trim(); if (/authorize/i.test(t)) { target = b; console.log('  clicking: ' + t); break } }
  if (!target) { console.log('  no Connect & authorize button found'); process.exit(1) }
  const nav = a.page.waitForNavigation({ waitUntil: 'load', timeout: 30000 }).catch(() => null)
  await target.click()
  await nav
  await new Promise(r => setTimeout(r, 1000))
  const u = new URL(a.page.url())
  console.log(`  landed on: ${u.origin}${u.pathname.slice(0, 40)}`)
  console.log(`  title: ${(await a.page.title()).slice(0, 80)}`)
  console.log(`  console errors: ${errors.length ? errors.join(' || ') : 'none'}`)
  await a.ctx.close()
} finally { await browser.close() }
