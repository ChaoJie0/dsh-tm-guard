// End-to-end acceptance: drive the REGISTERED tm_git_bloat tool (not the module)
// through apply(), against a throwaway real repo, plus the U-25 warnings.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'

__setExecOverride(async (f: string, a: string[]) => {
  if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
  if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
  if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
  throw new Error(`unexpected ${f} ${a.join(' ')}`)
})

const dir = mkdtempSync(join(tmpdir(), 'e2e-bloat-'))
const g = (args: string[]) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' })
g(['init', '-q']); g(['config', 'user.email', 't@t']); g(['config', 'user.name', 't'])
writeFileSync(join(dir, 'a.txt'), 'small\n')
g(['add', '-A']); g(['commit', '-qm', 'first commit'])
writeFileSync(join(dir, 'big-blob.bin'), Buffer.alloc(700 * 1024, 7))
g(['add', '-A']); g(['commit', '-qm', 'second commit adds big blob'])

const reg: any[] = []
const warns: string[] = []
const origWarn = console.warn, origLog = console.log
console.warn = (...a: unknown[]) => warns.push(a.map(String).join(' '))
console.log = () => {}
try {
  apply({ on() { return this as any }, tools: { register(t: any) { reg.push(t) } }, systemPrompt: { section() {} }, inject() {} } as any, { protectedPaths: [dir] })
} finally { console.warn = origWarn; console.log = origLog }

console.log('registered tools:', reg.map((t) => t.name).join(', '))
const tool = reg.find((t) => t.name === 'tm_git_bloat')
console.log('\n--- tool description (read-only claim) ---')
console.log(tool.description.slice(0, 200))

const head = g(['rev-parse', 'HEAD']).trim()
const out = await tool.execute({ path: dir })
console.log('\n--- tm_git_bloat output ---')
console.log(out)

const after = g(['rev-parse', 'HEAD']).trim()
console.log('\nHEAD before/after:', head === after ? 'UNCHANGED ✅' : 'MOVED ❌')
console.log('big blob detected:', out.includes('big-blob.bin') ? '✅' : '❌')
console.log('introducing commit shown:', /second commit adds big blob/.test(out) ? '✅' : '❌')

console.log('\n--- U-25 warnings (default config) ---')
console.log(warns.join('\n'))

const warns2: string[] = []
console.warn = (...a: unknown[]) => warns2.push(a.map(String).join(' ')); console.log = () => {}
try {
  apply({ on() { return this as any }, tools: { register() {} }, systemPrompt: { section() {} }, inject() {} } as any, { protectedPaths: [dir], failClosed: false, autoApprove: true })
} finally { console.warn = origWarn; console.log = origLog }
console.log('\n--- U-25 warnings (failClosed=false + autoApprove=true) ---')
console.log(warns2.join('\n'))

// Non-repo path
const plain = mkdtempSync(join(tmpdir(), 'e2e-plain-'))
console.log('\n--- non-repo behaviour ---')
console.log(await tool.execute({ path: plain }))

rmSync(dir, { recursive: true, force: true })
rmSync(plain, { recursive: true, force: true })
__setExecOverride(null)
