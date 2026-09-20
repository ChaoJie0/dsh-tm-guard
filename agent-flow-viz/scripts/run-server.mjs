#!/usr/bin/env node
/**
 * Standalone smoke-test / dev server for the visualization panel WITHOUT
 * loading it inside dsh. Seeds a few fake tool calls so you can preview the
 * UI. The real plugin is driven by dsh's tools/* events (see src/index.ts).
 *
 *   node scripts/run-server.mjs
 */
import { CallStore, summarizeArgs, summarizeResult } from '../lib/store.js'
import { startServer } from '../lib/server.js'

const store = new CallStore()
const port = Number(process.env.PORT || 3100)

const handle = await startServer(store, port)
console.log(`[run-server] panel at http://127.0.0.1:${handle.port} (Ctrl-C to stop)`)

// Seed a demo flow so the page is not empty.
let n = 0
const demos = [
  ['bash', { command: 'ls -la', description: 'list files' }],
  ['read', { file_path: 'src/index.ts' }],
  ['grep', { pattern: 'tools/post-execute', include: '*.ts' }],
  ['edit', { file_path: 'src/server.ts', old_string: 'a', new_string: 'b' }],
  ['bash', { command: 'npm run build', description: 'build the plugin' }],
]
for (const [tool, args] of demos) {
  const id = 'demo-' + ++n
  const { preview, json } = summarizeArgs(args)
  store.recordStart({
    id, tool, argsPreview: preview, argsJson: json, startedAt: Date.now() - (demos.length - n) * 900,
  })
  const fail = tool === 'bash' && args.command.includes('build') === false && false
  store.recordEnd(id, fail
    ? { status: 'error', error: 'command failed with exit code 1' }
    : { status: 'success', resultPreview: `[exit code 0] done (${Math.floor(Math.random() * 120) + 8}ms)` })
}

const shutdown = async () => { await handle.close(); process.exit(0) }
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
