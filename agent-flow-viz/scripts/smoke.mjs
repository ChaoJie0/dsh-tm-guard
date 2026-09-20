// Local smoke-test probe for the standalone demo server (127.0.0.1 only).
const base = 'http://127.0.0.1:' + (process.env.PORT || 3100)

const get = async (p) => {
  const r = await fetch(base + p)
  return { status: r.status, body: await r.text() }
}

let failures = 0
const check = (name, cond, extra = '') => {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? ' — ' + extra : ''))
  if (!cond) failures++
}

const health = await get('/api/health')
check('health 200', health.status === 200, health.body)
check('health ok', health.body.includes('"ok":true'))

const ev = await get('/api/events')
const data = JSON.parse(ev.body)
check('events 200', ev.status === 200)
check('seeded 5 calls', data.calls.length === 5, 'got ' + data.calls.length)
check('version > 0', data.version > 0)

const first = data.calls[0]
check('first has tool', typeof first.tool === 'string' && first.tool.length > 0, first.tool)
check('first has argsPreview', !!first.argsPreview)
check('first settled', first.status === 'success' && typeof first.durationMs === 'number',
  first.status + ' ' + first.durationMs)
check('first has resultPreview', !!first.resultPreview)

const running = data.calls.filter((c) => c.status === 'running')
check('no stuck running in demo seed', running.length === 0)

// Long-poll: asking with a stale version must resolve immediately.
const t0 = Date.now()
const lp = await get('/api/events?since=0')
check('long-poll resolves immediately for since=0', Date.now() - t0 < 1000)
check('long-poll returns calls', JSON.parse(lp.body).calls.length === 5)

const html = await get('/')
check('index served', html.status === 200)
check('index has svg canvas', html.body.includes('<svg'))
check('title present', html.body.includes('Agent Flow Viz'))

const clear = await fetch(base + '/api/clear', { method: 'POST' })
check('clear 200', clear.status === 200)
const after = JSON.parse((await get('/api/events')).body)
check('cleared buffer', after.calls.length === 0)

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
