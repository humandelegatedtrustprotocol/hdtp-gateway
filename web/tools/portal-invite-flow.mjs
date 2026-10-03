// The flow a person actually takes on a new node, with NO page reload between steps:
// register a passkey, create two identities on the Identity page, walk to People →
// Invites through the sidebar, create an invite. Prints what the page showed. This is
// the path that used to end in a silent 400 (see the commit that added it).
//   node tools/portal-invite-flow.mjs http://localhost:19080 out.png
import puppeteer from 'puppeteer-core'
const [A, out] = process.argv.slice(2)
const b = await puppeteer.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: 'new' })
const page = await b.newPage(); await page.setViewport({ width: 1440, height: 900 })
page.on('console', m => { if (m.type() === 'error') console.log('  [console]', m.text().slice(0, 160)) })
page.on('pageerror', e => console.log('  [pageerror]', String(e).slice(0, 160)))
const cdp = await page.createCDPSession(); await cdp.send('WebAuthn.enable')
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
await page.goto(A + '/setup', { waitUntil: 'load' }); await page.waitForSelector('#go')
const nav = page.waitForNavigation({ waitUntil: 'load' }).catch(() => {}); await page.click('#go'); await nav
// identity through the UI
const clickNav = async (label) => { const links = await page.$$('nav.side-nav a'); for (const l of links) { if ((await l.evaluate(e => e.textContent)).trim() === label) { await l.click(); break } } await new Promise(r => setTimeout(r, 900)) }
await clickNav('Identity'); await page.waitForSelector('#slug')
for (const [slug, name] of [['work', 'Alice'], ['alice1', 'Alice1']]) {
  await page.$eval('#slug', e => { e.value = '' }); await page.type('#slug', slug)
  await page.$eval('input[placeholder="Alice (work)"]', e => { e.value = '' }); await page.type('input[placeholder="Alice (work)"]', name)
  await page.click('main button'); await new Promise(r => setTimeout(r, 1500))
}
console.log('  session as the shell sees it:', JSON.stringify(await page.evaluate(() => ({ stored: localStorage.getItem('hdtp.account'), sidebarSelect: !!document.querySelector('.side-foot select') }))))
// invite through the UI, reached by the sidebar (no reload)
await clickNav('People'); await new Promise(r => setTimeout(r, 500))
const tabs = await page.$$('.tabs a'); for (const t of tabs) { if ((await t.evaluate(e => e.textContent)).includes('Invites')) { await t.click(); break } }
await page.waitForSelector('main')
await new Promise(r => setTimeout(r, 800))
await page.type('input[placeholder="dinner group"]', 'from the ui')
const btns = await page.$$('main button'); for (const bt of btns) { const t = await bt.evaluate(e => e.textContent); if (t.trim() === 'Create') { await bt.click(); break } }
await new Promise(r => setTimeout(r, 2000))
const state = await page.evaluate(() => ({
  url: location.href,
  notice: document.querySelector('.notice')?.textContent?.slice(0, 200) || null,
  warn: document.querySelector('.warn')?.textContent?.slice(0, 200) || null,
  rows: [...document.querySelectorAll('tbody tr')].map(r => r.textContent.replace(/\s+/g, ' ').slice(0, 80)),
}))
console.log('  after Create:', JSON.stringify(state, null, 1))
await page.screenshot({ path: out, fullPage: true }); console.log('  shot', out)
await b.close()
