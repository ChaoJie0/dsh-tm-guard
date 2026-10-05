// U-19 — platform capability probe + explicit degradation notice.
//
// The plugin's snapshot/rollback machinery is macOS-only (`tmutil`). On any
// other platform the pre-U-19 behaviour was the worst possible one for a
// SAFETY tool: a few `tm_*` tools failed at call time while the gate kept
// speaking fail-closed language about Time Machine protection. A user could
// reasonably conclude a rollback net existed when none did. Silent degradation
// in a permission gate is the bug — not the missing platform support.
//
// These tests lock the contract for non-darwin hosts:
//   a. apply() prints a prominent console.error naming the platform
//   b. the gate does NOT block writes for a missing TM net (no tmutil to check)
//   c. the degradation is warned about once per apply(), not per call
//   d. tm_status labels the mode `limited mode (no TM)`
//
// `process.platform` is a read-only own accessor on the `process` object, so it
// is stubbed with Object.defineProperty and restored in a finally/after hook —
// the plugin reads it fresh at apply() time.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'
import { __setGitOverride } from './src/git.ts'

const REAL_PLATFORM = process.platform

/** Temporarily present `process.platform` as `value`. Returns a restore fn. */
function stubPlatform(value: string): () => void {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform')!
  Object.defineProperty(process, 'platform', { ...desc, value })
  return () => { Object.defineProperty(process, 'platform', desc) }
}

/** Capture console.error / console.warn / console.log around a callback. */
function captureConsole(fn: () => void): { errors: string[]; warns: string[] } {
  const errors: string[] = []
  const warns: string[] = []
  const origError = console.error
  const origWarn = console.warn
  const origLog = console.log
  console.error = (...a: unknown[]) => { errors.push(a.map(String).join(' ')) }
  console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
  console.log = () => {}
  try {
    fn()
  } finally {
    console.error = origError
    console.warn = origWarn
    console.log = origLog
  }
  return { errors, warns }
}

let ORIG_CWD = ''
let ROOT = '' // protected temp root, also a git repo (writes resolve a baseline)
let hooks: Record<string, any[]>
let registered: any[]

function mockCtx() {
  hooks = {}
  registered = []
  return {
    on(ev: string, fn: any) { (hooks[ev] ??= []).push(fn); return this },
    tools: { register(t: any) { registered.push(t) } },
    systemPrompt: { section() {} },
    inject() {},
  }
}

function next() { return Promise.resolve({ kind: 'allow', reason: 'next' }) }
async function gate(exec: any) {
  return hooks['tools/pre-execute'][0](exec, next)
}

/** Apply with the given platform; returns captured console output + ctx. */
function applyAs(platform: string, config: Record<string, unknown> = {}) {
  const restore = stubPlatform(platform)
  let cap: { errors: string[]; warns: string[] } = { errors: [], warns: [] }
  try {
    const ctx = mockCtx()
    cap = captureConsole(() => { apply(ctx as any, { protectedPaths: [ROOT], ...config } as any) })
    return { ctx, ...cap }
  } finally {
    restore()
  }
}

/** Run `fn` while `process.platform` reads as `platform`. */
async function asPlatform<T>(platform: string, fn: () => Promise<T>): Promise<T> {
  const restore = stubPlatform(platform)
  try {
    return await fn()
  } finally {
    restore()
  }
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-platform-'))
  execSync(`git init -q ${ROOT} && git -C ${ROOT} config user.email t@t && git -C ${ROOT} config user.name t`)
  execSync(`echo base > ${join(ROOT, 'base.txt')} && git -C ${ROOT} add -A && git -C ${ROOT} commit -qm baseline`)
  process.chdir(ROOT)
  // tmutil is "callable" so any accidental TM path surfaces as a wrong call
  // rather than a crash; the point of U-19 is that it must NOT be reached.
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    if (a[0] === 'localsnapshot') {
      throw new Error('tmutil: not available on this platform')
    }
    if (a[0] === 'startbackup') throw new Error('tmutil: not available on this platform')
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
})

after(() => {
  __setExecOverride(null)
  __setGitOverride(null)
  process.chdir(ORIG_CWD)
  rmSync(ROOT, { recursive: true, force: true })
})

beforeEach(() => {
  // Guard against a leaked stub making later tests machine-dependent.
  assert.equal(process.platform, REAL_PLATFORM, 'process.platform leaked from a previous test')
})

test('U-19a: non-darwin apply() emits a prominent console.error naming the platform', () => {
  const { errors } = applyAs('linux')
  const banner = errors.find((l) => l.includes('[tm-guard]') && l.includes('linux'))
  assert.ok(banner, `expected a platform error banner, got: ${JSON.stringify(errors)}`)
  // The message must carry all three facts: which platform, why it fails, and
  // what the gate falls back to. A vague "unsupported" would not be actionable.
  assert.match(banner!, /不受支持/)
  assert.match(banner!, /tmutil/)
  assert.match(banner!, /git baseline/)
})

test('U-19a: darwin apply() emits NO platform error (no false alarm on the supported host)', () => {
  const { errors } = applyAs('darwin')
  assert.equal(
    errors.filter((l) => l.includes('不受支持')).length,
    0,
    `darwin must not report an unsupported platform: ${JSON.stringify(errors)}`,
  )
})

test('U-19b: non-darwin gate ALLOWS a write (no TM net to fail closed on)', async () => {
  applyAs('linux')
  const r = await asPlatform('linux', () =>
    gate({ name: 'write', arguments: { path: join(ROOT, 'out.txt'), content: 'x' } }),
  )
  assert.equal(
    r.kind,
    'allow',
    `a write on a non-darwin host must not be blocked for a missing TM net: ${JSON.stringify(r)}`,
  )
})

test('U-19b: non-darwin gate warns once about the missing platform, not per call', async () => {
  applyAs('linux')
  const warns = await asPlatform('linux', async () => {
    const seen: string[] = []
    const orig = console.warn
    console.warn = (...a: unknown[]) => { seen.push(a.map(String).join(' ')) }
    try {
      for (let i = 0; i < 3; i++) {
        const r = await gate({ name: 'write', arguments: { path: join(ROOT, `f${i}.txt`), content: 'x' } })
        assert.equal(r.kind, 'allow')
      }
    } finally {
      console.warn = orig
    }
    return seen
  })
  const platformWarns = warns.filter((l) => l.includes('平台不支持'))
  assert.equal(
    platformWarns.length,
    1,
    `expected exactly one platform warning across 3 writes, got ${platformWarns.length}: ${JSON.stringify(platformWarns)}`,
  )
})

test('U-19b: darwin gate emits no platform warning at all', async () => {
  applyAs('darwin')
  const warns = await asPlatform('darwin', async () => {
    const seen: string[] = []
    const orig = console.warn
    console.warn = (...a: unknown[]) => { seen.push(a.map(String).join(' ')) }
    try {
      await gate({ name: 'write', arguments: { path: join(ROOT, 'darwin.txt'), content: 'x' } })
    } finally {
      console.warn = orig
    }
    return seen
  })
  assert.equal(
    warns.filter((l) => l.includes('平台不支持')).length,
    0,
    `darwin must never warn about platform support: ${JSON.stringify(warns)}`,
  )
})

test('U-19c: tm_status on non-darwin labels limited mode and N/A health', async () => {
  applyAs('linux')
  const tool = registered.find((t) => t.name === 'tm_status')
  assert.ok(tool, 'tm_status must be registered')
  const out: string = await asPlatform('linux', () => Promise.resolve(tool.execute({})))
  assert.match(out, /Platform\s*:\s*linux — limited mode \(no TM\)/)
  assert.match(out, /N\/A — no TM on this platform/)
  assert.doesNotMatch(
    out,
    /UNHEALTHY 🚫 — writes BLOCKED/,
    'limited mode must not report a fixable TM fault that would block writes',
  )
  // The fallback net must be named, so the reader knows what still protects them.
  assert.match(out, /git baseline is the rollback net/)
})

test('U-19c: tm_status on darwin labels full mode', async () => {
  applyAs('darwin')
  const tool = registered.find((t) => t.name === 'tm_status')
  const out: string = await asPlatform('darwin', () => Promise.resolve(tool.execute({})))
  assert.match(out, /Platform\s*:\s*darwin — full mode/)
  assert.doesNotMatch(out, /limited mode/)
})

test('U-19: non-darwin snapshot path never calls tmutil (no spurious failures)', async () => {
  applyAs('linux')
  // Record every exec the tm seam is asked to perform. On a non-darwin host
  // the snapshot branch must be skipped entirely, so `localsnapshot` must not
  // appear — otherwise every write would log a failure the user cannot fix.
  const calls: string[] = []
  __setExecOverride(async (f: string, a: string[]) => {
    calls.push(`${f} ${a.join(' ')}`)
    if (a[0] === 'localsnapshot') throw new Error('tmutil: not available on this platform')
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
  try {
    const r = await asPlatform('linux', () =>
      gate({ name: 'write', arguments: { path: join(ROOT, 'no-tm.txt'), content: 'x' } }),
    )
    assert.equal(r.kind, 'allow')
    assert.equal(
      calls.filter((c) => c.includes('localsnapshot')).length,
      0,
      `non-darwin must not attempt a snapshot: ${JSON.stringify(calls)}`,
    )
  } finally {
    __setExecOverride(null)
  }
})

test('U-19: non-darwin blocking-backup mode does not deny every write', async () => {
  // blockingBackupBeforeWrite is a fail-closed branch: if the backup command
  // fails the write is DENIED. Off macOS that command can only fail, so
  // without the platform guard this option would brick every write.
  applyAs('linux', { blockingBackupBeforeWrite: true })
  const r = await asPlatform('linux', () =>
    gate({ name: 'write', arguments: { path: join(ROOT, 'blocking.txt'), content: 'x' } }),
  )
  assert.equal(
    r.kind,
    'allow',
    `blockingBackupBeforeWrite must not deny writes on a non-darwin host: ${JSON.stringify(r)}`,
  )
})
