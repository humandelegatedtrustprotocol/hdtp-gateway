// Does an OAuth-protected MCP server's sign-in flow start through this node?
//   node tools/portal-oauth-probe.mjs http://localhost:19080 https://mcp.batondeck.com/mcp
// Registers a virtual passkey, creates an identity, adds the server as a
// streamable-http + oauth integration, and follows /integrations/{id}/authorize
// far enough to see where it sends the browser — i.e. whether discovery and
// dynamic client registration succeeded. It never signs in: that is the owner's.
import puppeteer from 'puppeteer-core'
const [A, endpoint] = process.argv.slice(2)
const b = await puppeteer.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: 'new' })
try {
  const page = await b.newPage()
  const cdp = await page.createCDPSession(); await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  await page.goto(A + '/setup', { waitUntil: 'load' }); await page.waitForSelector('#go')
  const nav = page.waitForNavigation({ waitUntil: 'load' }).catch(() => {}); await page.click('#go'); await nav
  const post = (path, fields) => page.evaluate(async ({ path, fields }) => {
    const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
    const body = new URLSearchParams({ csrf, account: localStorage.getItem('pact.account') || '', ...fields })
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Pact-Csrf': csrf }, body: body.toString(), redirect: 'manual' })
    return { status: r.status, url: r.url, body: (await r.text()).slice(0, 200) }
  }, { path, fields })
  await post('/identity/create', { slug: 'alice', name: 'Alice', algo: 'p256' })
  await page.goto(A + '/', { waitUntil: 'load' })
  const created = await post('/integrations/create', { slug: 'batondeck', transport: 'streamable-http', endpoint, auth_kind: 'oauth' })
  console.log('  create:', created.status, created.body.replace(/\s+/g, ' ').slice(0, 120))
  const list = await page.evaluate(async () => (await fetch('/api/integrations?account=' + encodeURIComponent(localStorage.getItem('pact.account') || ''), { headers: { Accept: 'application/json' } })).json())
  const row = (list.rows || [])[0]
  console.log('  integration:', row ? `${row.Slug} ${row.Transport} ${row.AuthKind} status=${row.Status}` : JSON.stringify(list).slice(0, 160))
  if (!row) process.exit(1)
  // The flow starts on /connect (the portal's Connect/Authorize buttons post there);
  // /authorize only waits for the URL that produces.
  const conn = await post('/integrations/' + row.ID + '/connect', {})
  console.log('  connect:', conn.status)
  // A manual-redirect fetch hides the Location; navigate instead and read where we land.
  const resp = await page.goto(A + '/integrations/' + row.ID + '/authorize?account=' + encodeURIComponent(await page.evaluate(() => localStorage.getItem('pact.account') || '')), { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(e => ({ err: String(e) }))
  const where = page.url()
  const u = new URL(where)
  console.log('  browser landed on:', u.origin + u.pathname)
  if (u.searchParams.has('client_id')) console.log('  authorize params:', ['client_id', 'redirect_uri', 'code_challenge_method', 'scope', 'resource'].map(k => `${k}=${(u.searchParams.get(k) || '').slice(0, 60)}`).join(' '))
  else console.log('  page text:', (await page.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ').slice(0, 300))
} finally { await b.close() }
