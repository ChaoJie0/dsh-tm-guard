// Integration test: load src/index.ts under Node strip-types with a mock
// Cordis context, fire synthetic pre/post-execute events, and verify the
// recorded flow is served over HTTP. Run with the dsh resolve hook so the
// @deepseek-ai/* peer imports resolve.
import { apply } from '../src/index.ts'

const listeners = {}
const calls = []

const ctx = {
  on(name, fn) {
    ;(listeners[name] ||= []).push(fn)
    return () => {
      listeners[name] = (listeners[name] || []).filter((f) => f !== fn)
    }
  },
  effect(fn) {
    // Run and retain the disposer (real Cordis runs it on fiber unload).
    const dispose = fn()
    return { dispose: async () => dispose && dispose() }
  },
  tools: { register() {} },
}

const port = 3199
apply(ctx, { port, verbose: false })

const callId = 'test-1'
// pre-execute: observer must call next() and return its decision.
let nextCalled = 0
const pre = listeners['tools/pre-execute'][0]
const decision = await pre(
  { name: 'bash', arguments: { command: 'echo hi', description: 'greet' }, callId },
  async () => { nextCalled++; return { kind: 'allow' } },
)
console.log('pre decision', JSON.stringify(decision), 'nextCalled', nextCalled)

// post-execute: success result.
const post = listeners['tools/post-execute'][0]
let postNext = 0
const postDecision = await post(
  { name: 'bash', arguments: { command: 'echo hi' }, callId },
  { isError: false, value: 0, content: [{ type: 'text', text: '[exit code 0] hi' }] },
  async () => { postNext++; return { kind: 'accept' } },
)
console.log('post decision', JSON.stringify(postDecision), 'nextCalled', postNext)

// A failing tool.
await pre(
  { name: 'read', arguments: { file_path: '/nope' }, callId: 'test-2' },
  async () => ({ kind: 'allow' }),
)
await post(
  { name: 'read', arguments: { file_path: '/nope' }, callId: 'test-2' },
  { isError: true, error: { name: 'Error', message: 'file not found' }, content: [] },
  async () => ({ kind: 'accept' }),
)

// Give the server a moment to bind, then read the API.
await new Promise((r) => setTimeout(r, 300))
const r = await fetch('http://127.0.0.1:' + port + '/api/events')
const data = await r.json()
console.log('served calls:', data.calls.length)
for (const c of data.calls) {
  console.log(' -', c.id, c.tool, c.status, c.durationMs + 'ms',
    JSON.stringify(c.argsPreview), c.error ? 'ERR=' + c.error : '')
}

let ok = true
ok &&= nextCalled === 1
ok &&= postNext === 1
ok &&= data.calls.length === 2
ok &&= data.calls[0].tool === 'bash' && data.calls[0].status === 'success'
ok &&= data.calls[0].argsPreview === 'echo hi'
ok &&= data.calls[0].resultPreview.includes('hi')
ok &&= typeof data.calls[0].durationMs === 'number'
ok &&= data.calls[1].status === 'error' && data.calls[1].error === 'file not found'

console.log(ok ? '\nPLUGIN INTEGRATION PASSED' : '\nPLUGIN INTEGRATION FAILED')
process.exit(ok ? 0 : 1)
