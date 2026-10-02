// Config robustness: apply() must survive malformed rawConfig (a user hand-
// editing cordis.patch.yml can easily pass a string where an array belongs,
// a number where a boolean belongs, etc.) and the gate must keep working.
// Also: concurrent gate invocations (dsh can issue parallel tool calls).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'

let ORIG_CWD = process.cwd()
let ROOT = ''
let hooks: Record<string, any[]>

function mockCtx() {
  hooks = {}
  return {
    on(ev: string, fn: any) { (hooks[ev] ??= []).push(fn); return this },
    tools: { register() {} },
    systemPrompt: { section() {} },
    inject() {},
  }
}

function tmHealthy() {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    if (a[0] === 'localsnapshot') return { stdout: 'com.apple.TimeMachine.2026-10-02-100000.local\n' }
    if (a[0] === 'startbackup') return { stdout: '' }
    if (f === '/bin/df') return { stdout: 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n' }
    if (f === '/sbin/mount_apfs' || f === '/sbin/umount' || f === '/bin/cp') return { stdout: '' }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
}

function next() { return Promise.resolve({ kind: 'allow', reason: 'next' }) }
function gate(exec: any) {
  return hooks['tools/pre-execute'][0](exec, next)
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-cfg-'))
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  process.chdir(ORIG_CWD)
})

// --- malformed config matrix -------------------------------------------
const BAD_CONFIGS: Array<[string, any]> = [
  ['null', null],
  ['undefined', undefined],
  ['empty object', {}],
  ['protectedPaths as string', { protectedPaths: '/tmp/one-path' }],
  ['protectedPaths empty array', { protectedPaths: [] }],
  ['denyReadPaths as string', { denyReadPaths: '~/.ssh' }],
  ['extraAllowTools as string', { extraAllowTools: 'bash' }],
  ['extraDenyTools as number', { extraDenyTools: 42 }],
  ['failClosed as string', { failClosed: 'yes' }],
  ['denyNetwork as number', { denyNetwork: 0 }],
  ['verbose as string', { verbose: 'true' }],
  ['snapshotCooldown negative', { snapshotCooldownSeconds: -5 }],
  ['requireGitBaseline null', { requireGitBaseline: null }],
  ['blockingBackup as number', { blockingBackupBeforeWrite: 1 }],
  ['autoApprove as string', { autoApprove: 'yes' }],
  ['turnReports as string', { turnReports: 'no' }],
  ['denyReadPaths empty array', { denyReadPaths: [] }],
  ['protectedPaths with trailing slash', { protectedPaths: ['/tmp/x/'] }],
]

for (const [label, cfg] of BAD_CONFIGS) {
  test(`config robustness: apply survives "${label}" and gate still works`, async () => {
    tmHealthy()
    try {
      apply(mockCtx() as any, cfg)
      const r1 = await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } })
      assert.equal(r1.kind, 'deny', `network should still deny under ${label}`)
      const r2 = await gate({ name: 'Read', arguments: { file_path: '/tmp/x.txt' } })
      assert.ok(r2.kind === 'allow' || r2.kind === 'deny', `gate should still decide under ${label}`)
    } finally { __setExecOverride(null) }
  })
}

// --- concurrency --------------------------------------------------------
test('gate: 100 concurrent mixed calls stay correct; audit jsonl stays valid', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], snapshotCooldownSeconds: 0 })
    const calls = Array.from({ length: 100 }, (_, i) =>
      i % 2 === 0
        ? gate({ name: 'bash', arguments: { command: `curl -s https://evil${i}.example/x` } })
        : gate({ name: 'Read', arguments: { file_path: '/tmp/ok.txt' } }))
    const results = await Promise.all(calls)
    for (let i = 0; i < results.length; i++) {
      if (i % 2 === 0) {
        assert.equal(results[i].kind, 'deny', `even #${i} (network) should deny`)
      } else {
        assert.equal(results[i].kind, 'allow', `odd #${i} (read) should allow`)
      }
    }
    // audit jsonl must remain a valid line-per-record file
    const logPath = join(ROOT, '.tm-guard', 'audit.jsonl')
    assert.ok(existsSync(logPath))
    const lines = readFileSync(logPath, 'utf8').trim().split('\n')
    assert.ok(lines.length >= 100, `expected >=100 audit lines, got ${lines.length}`)
    for (const ln of lines) {
      const rec = JSON.parse(ln) // throws on corruption
      assert.ok(rec.decision === 'allow' || rec.decision === 'deny')
    }
  } finally { __setExecOverride(null) }
})

test('gate: concurrent writes to the same git baseline do not corrupt', async () => {
  tmHealthy()
  try {
    const repo = join(ROOT, 'repo')
    execSync(`git init -q ${repo} && git -C ${repo} config user.email t@t && git -C ${repo} config user.name t`)
    execSync(`echo base > ${join(repo, 'base.txt')} && git -C ${repo} add -A && git -C ${repo} commit -qm baseline`)
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const calls = Array.from({ length: 30 }, (_, i) =>
      gate({ name: 'Write', arguments: { file_path: join(repo, `c${i}.txt`), content: 'x' } }))
    const results = await Promise.all(calls)
    for (const r of results) assert.equal(r.kind, 'allow')
    // The gate does not execute writes (dsh does) — what must hold is that
    // concurrent git-baseline operations leave the repo healthy.
    execSync(`git -C ${repo} status --porcelain`, { encoding: 'utf8' }) // throws if repo broken
    const log = execSync(`git -C ${repo} log --oneline`, { encoding: 'utf8' })
    assert.ok(log.includes('baseline'), 'baseline commit intact')
    const branches = execSync(`git -C ${repo} branch --list`, { encoding: 'utf8' })
    assert.ok(branches.includes('master') || branches.includes('main'), 'branch intact')
  } finally { __setExecOverride(null) }
})
