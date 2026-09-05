// A minimal MCP Streamable HTTP client, enough to drive a node's owner surface.
export async function connect(base, token) {
  let sid = null
  const rpc = async (method, params, id) => {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer ' + token }
    if (sid) headers['Mcp-Session-Id'] = sid
    const r = await fetch(base + '/owner/mcp', { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', ...(id === undefined ? {} : { id }), method, params }) })
    if (r.headers.get('Mcp-Session-Id')) sid = r.headers.get('Mcp-Session-Id')
    if (id === undefined) return null
    const text = await r.text()
    if (!r.ok) throw new Error(`${method}: ${r.status} ${text.slice(0, 200)}`)
    // SSE or plain JSON
    const line = text.split('\n').find(l => l.startsWith('data:'))
    const body = JSON.parse(line ? line.slice(5).trim() : text)
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error).slice(0, 200)}`)
    return body.result
  }
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'pact-qa', version: '1' } }, 1)
  await rpc('notifications/initialized', {})
  let n = 1
  return {
    tools: async () => (await rpc('tools/list', {}, ++n)).tools.map(t => t.name),
    call: async (name, args) => {
      const res = await rpc('tools/call', { name, arguments: args || {} }, ++n)
      const text = (res.content || []).map(c => c.text).join('')
      try { return JSON.parse(text) } catch { return text }
    },
    raw: rpc,
  }
}
