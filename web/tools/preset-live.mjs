// Proves the preset rule against a running node: a label survives only while the grant
// still is that bundle. Restores whatever it changed before it exits.
import { launch, openNode } from './portal-login.mjs'

const save = (node, fpr, perms, extra = {}) => node.page.evaluate(async ({ fpr, perms, extra }) => {
  const csrf = (document.cookie.split('; ').find(c => c.startsWith('pact_csrf')) || '').split('=').slice(1).join('=')
  const body = new URLSearchParams({ csrf, account: localStorage.getItem('pact.account') || '', ...extra })
  for (const p of perms) body.append('perm', p)
  const r = await fetch('/contacts/' + encodeURIComponent(fpr) + '/permissions', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Pact-Csrf': csrf }, body: body.toString(),
  })
  return r.status
}, { fpr, perms, extra })

const b = await launch()
try {
  const a = await openNode(b, 'alice', 'http://localhost:18120')
  const fpr = (await a.get('/api/conversations')).contacts[0].fingerprint
  const read = async () => {
    const p = await a.get('/api/contacts/' + encodeURIComponent(fpr))
    return { preset: p.preset, on: p.permissions.filter(x => x.on).map(x => x.name) }
  }
  const before = await read()
  console.log('  as found      : preset=' + JSON.stringify(before.preset) + '  grants=' + before.on.join(','))

  const trimmed = before.on.filter(p => p !== 'status.view')
  await save(a, fpr, trimmed)
  const hand = await read()
  console.log('  hand-toggled  : preset=' + JSON.stringify(hand.preset) + '  grants=' + hand.on.join(','))

  await save(a, fpr, [], { preset: before.preset, apply_preset: '1' })
  const back = await read()
  console.log('  preset applied: preset=' + JSON.stringify(back.preset) + '  grants=' + back.on.join(','))

  const ok = hand.preset === '' && back.preset === before.preset &&
    back.on.slice().sort().join() === before.on.slice().sort().join()
  console.log(ok ? '\n  PASS — the label cleared on a hand edit and came back with the preset, integration grant intact'
                 : '\n  FAIL — see above')
  await a.ctx.close()
} finally { await b.close() }
