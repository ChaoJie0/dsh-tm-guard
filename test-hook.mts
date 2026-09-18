// Verifies the pre-execute gate reads dsh's ToolExecution fields correctly.
// dsh passes exec = { name, arguments, callId, ... } — NOT { tool, args, input }.
// This replicates exactly the extraction + classification the hook performs.
import { classifyToolCall, decide } from './src/classifier.ts'

let pass = 0
let fail = 0
function check(label: string, execLike: { name: string; arguments: unknown }, opts: {
  allow: boolean
  category: string
  paths?: string[]
}, protectedPaths = ['/tmp/tm-guard-home']) {
  // Mirror src/index.ts gate extraction:
  const toolName = (execLike as any).name ?? 'unknown'
  const args = ((execLike as any).arguments ?? {}) as Record<string, unknown>
  const c = classifyToolCall(toolName, args)

  // Path protection (only file_write with paths is checked in index.ts)
  let pathsProtected = true
  if (c.category === 'file_write' && c.targetPaths.length > 0) {
    pathsProtected = c.targetPaths.every((p: string) => {
      const abs = p.startsWith('/') ? p : `${process.cwd()}/${p}`
      return protectedPaths.some((pref) => abs === pref || abs.startsWith(pref + '/'))
    })
  }
  const d = decide(c, pathsProtected)

  const okCat = c.category === opts.category
  const okAllow = d.allow === opts.allow
  const okPaths = !opts.paths || opts.paths.every((p) => c.targetPaths.includes(p))
  if (okCat && okAllow && okPaths) { pass++; console.log(`PASS: ${label}`) }
  else {
    fail++
    console.log(`FAIL: ${label}\n  expected cat=${opts.category} allow=${opts.allow} paths=${opts.paths}\n  got      cat=${c.category} allow=${d.allow} paths=${JSON.stringify(c.targetPaths)}\n  reason: ${c.reason}`)
  }
}

// dsh `write` tool: name="write", arguments.file_path — the case the user hit.
check('write tool (protected path)',
  { name: 'write', arguments: { file_path: '/tmp/tm-guard-temp/test.txt', content: 'hi' } },
  { allow: true, category: 'file_write', paths: ['/tmp/tm-guard-temp/test.txt'] })

check('write tool (OUTSIDE prefix -> deny)',
  { name: 'write', arguments: { file_path: '/etc/hosts', content: 'x' } },
  { allow: false, category: 'file_write' })

// dsh `bash` tool: name="bash", arguments.command — previously all seen as empty -> read.
check('bash curl (must BLOCK)',
  { name: 'bash', arguments: { command: 'curl https://example.com', description: 'fetch' } },
  { allow: false, category: 'network' })

check('bash sudo rm (must BLOCK)',
  { name: 'bash', arguments: { command: 'sudo rm -rf /etc/foo', description: 'x' } },
  { allow: false, category: 'process' })

check('bash rm -rf / (catastrophic, must BLOCK)',
  { name: 'bash', arguments: { command: 'rm -rf /', description: 'x' } },
  { allow: false, category: 'system' })

check('bash local write on protected path (allow)',
  { name: 'bash', arguments: { command: 'echo hi > "/tmp/tm-guard-temp/a.txt"', description: 'write' } },
  { allow: true, category: 'file_write' })

check('bash npm install (must BLOCK)',
  { name: 'bash', arguments: { command: 'npm install', description: 'install deps' } },
  { allow: false, category: 'network' })

check('bash read-only ls (allow)',
  { name: 'bash', arguments: { command: 'ls -la', description: 'list' } },
  { allow: true, category: 'read' })

// tm_* internal tools always allowed
check('tm_status internal',
  { name: 'tm_status', arguments: {} },
  { allow: true, category: 'read' })

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
