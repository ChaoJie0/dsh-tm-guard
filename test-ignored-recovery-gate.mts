// Gate-integration tests for ignored-file recovery (proposal §Tests).
//
// These drive src/index.ts apply() through the tools/pre-execute hook with a
// REAL local git repo and an injected tmutil layer, asserting the end-to-end
// contract: ignored targets force one fresh pre-write snapshot (before the
// file is gone) even inside cooldown; tracked targets do not; the audit
// record carries per-target gitRecovery; a forced snapshot obeys the cooldown
// afterwards; probe/commit failures never deny and downgrade honestly.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  mkdtempSync,
  writeFileSync,
  existsSync,
  rmSync,
  readFileSync,
  realpathSync,
  appendFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { apply, __resetSnapshotClockForTests } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'
import { __setGitOverride, __setGitProbeOverride } from './src/git.ts'

let ORIG_CWD: string
let ROOT: string
let REPO: string
let hooks: Record<string, any[]>
let registered: any[]
let auditPath: string

// Snapshot instrumentation.
let snapshotCalls = 0
let snapshotFailures = 0
let lastSnapshotPathExisted: boolean | null = null
let snapSeq = 0

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

/** Healthy TM with instrumented localsnapshot. */
function tmHealthy(customSnapshot?: () => { stdout: string }) {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-20-120000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    if (a[0] === 'localsnapshot') {
      if (customSnapshot) return customSnapshot()
      snapshotCalls++
      if (snapshotFailures > 0) {
        snapshotFailures--
        throw new Error('snapshot denied: EPERM')
      }
      snapSeq++
      const date = `2026-10-20-13${String(snapSeq).padStart(4, '0')}`
      return { stdout: `Created local snapshot with date: ${date}\n` }
    }
    if (a[0] === 'startbackup') return { stdout: '' }
    if (f === '/bin/df') return { stdout: 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n' }
    if (f === '/sbin/mount_apfs' || f === '/sbin/umount' || f === '/bin/cp') return { stdout: '' }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
}

function next() { return Promise.resolve({ kind: 'allow', reason: 'next' }) }
async function gate(exec: any) {
  return hooks['tools/pre-execute'][0](exec, next)
}
function applyGate(cfg: Record<string, unknown> = {}) {
  apply(mockCtx() as any, {
    protectedPaths: [ROOT],
    verbose: false,
    snapshotCooldownSeconds: 300, // large window so a forced snapshot is observable
    ...cfg,
  })
}
function lastAudit(): any {
  const all = readFileSync(auditPath, 'utf8').trim().split('\n')
  return JSON.parse(all[all.length - 1])
}
function findTool(name: string) { return registered.find((t) => t.name === name) }

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'ifr-gate-')))
  REPO = join(ROOT, 'repo')
  execSync(`git init -q ${REPO}`)
  execSync(`git -C ${REPO} config user.email t@t`)
  execSync(`git -C ${REPO} config user.name t`)
  auditPath = join(ROOT, '.tm-guard', 'audit.jsonl')
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  __setGitOverride(null)
  __setGitProbeOverride(null)
  process.chdir(ORIG_CWD)
  rmSync(ROOT, { recursive: true, force: true })
})
beforeEach(() => {
  __resetSnapshotClockForTests()
  snapshotCalls = 0
  snapshotFailures = 0
  lastSnapshotPathExisted = null
  snapSeq = 0
  __setGitOverride(null)
  __setGitProbeOverride(null)
})

/** Reset the repo to a clean committed baseline, then add fixtures. */
function setupRepoFiles() {
  // Drop any prior work (prime files, checkpoint commits) back to an empty
  // tree so each test starts identical and the commit below always has work.
  execSync(`git -C ${REPO} reset -q --hard`, { stdio: 'ignore' })
  execSync(`git -C ${REPO} clean -fdxq`, { stdio: 'ignore' })
  writeFileSync(join(REPO, '.gitignore'), '.env.*\n')
  writeFileSync(join(REPO, 'tracked.txt'), `tracked-${Math.random()}`)
  writeFileSync(join(REPO, 'forced.env'), `force-${Math.random()}`)
  writeFileSync(join(REPO, '.env.local'), `secret-${Math.random()}`)
  execSync(`git -C ${REPO} add tracked.txt`)
  execSync(`git -C ${REPO} add -f forced.env`)
  execSync(`git -C ${REPO} commit -qm base-${Date.now()}`)
}

test('gate: tracked file delete -> yes, no forced snapshot', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime.txt'), content: 'x' } })
  assert.ok(snapshotCalls >= 1, 'prime write creates a snapshot')
  const callsBefore = snapshotCalls
  const r = await gate({
    name: 'bash',
    arguments: { command: `rm ${join(REPO, 'tracked.txt')}`, description: 'delete tracked' },
  })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore, 'tracked delete must not force a snapshot in cooldown')
  const rec = lastAudit()
  assert.equal(rec.decision, 'allow')
  assert.deepEqual(rec.gitRecovery, [{ path: join(REPO, 'tracked.txt'), state: 'yes' }])
})

test('gate: ignored delete in cooldown forces a fresh snapshot BEFORE the file vanishes (M1)', async () => {
  setupRepoFiles()
  const ignored = join(REPO, '.env.local')
  tmHealthy(() => {
    snapshotCalls++
    lastSnapshotPathExisted = existsSync(ignored)
    snapSeq++
    return { stdout: `Created local snapshot with date: 2026-10-20-14${String(snapSeq).padStart(4, '0')}\n` }
  })
  applyGate()
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime2.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  assert.ok(callsBefore >= 1)
  assert.ok(existsSync(ignored), 'precondition: ignored file exists')
  const r = await gate({
    name: 'bash',
    arguments: { command: `rm ${ignored}`, description: 'delete ignored secret' },
  })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore + 1, 'ignored target forces exactly one fresh snapshot')
  assert.equal(lastSnapshotPathExisted, true, 'forced snapshot observed the file still on disk')
  const rec = lastAudit()
  assert.deepEqual(rec.gitRecovery, [{ path: ignored, state: 'no' }])
  assert.ok(rec.snapshotId, 'audit records the forced snapshot id')
})

test('gate: mixed rm tracked + ignored -> both details, force by the no entry (M2)', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  const tracked = join(REPO, 'tracked.txt')
  const ignored = join(REPO, '.env.local')
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime3.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  const r = await gate({
    name: 'bash',
    arguments: { command: `rm ${tracked} ${ignored}`, description: 'mixed delete' },
  })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore + 1, 'one no target forces the snapshot')
  const rec = lastAudit()
  assert.ok(Array.isArray(rec.gitRecovery))
  assert.deepEqual(
    rec.gitRecovery.map((g: any) => [g.path.split('/').pop(), g.state]).sort(),
    [['.env.local', 'no'], ['tracked.txt', 'yes']].sort(),
  )
})

test('gate: skip-worktree tracked file -> unrecoverable, forces fresh snapshot (anti false-yes)', async () => {
  setupRepoFiles()
  const skipFile = join(REPO, 'skip.txt')
  writeFileSync(skipFile, `skip-${Math.random()}`)
  execSync(`git -C ${REPO} add skip.txt`)
  execSync(`git -C ${REPO} commit -qm skip`)
  execSync(`git -C ${REPO} update-index --skip-worktree skip.txt`)
  tmHealthy(() => {
    snapshotCalls++
    lastSnapshotPathExisted = existsSync(skipFile)
    snapSeq++
    return { stdout: `Created local snapshot with date: 2026-10-20-15${String(snapSeq).padStart(4, '0')}\n` }
  })
  applyGate()
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime5.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  assert.ok(existsSync(skipFile), 'precondition: skip-worktree file exists')
  const r = await gate({
    name: 'bash',
    arguments: { command: `rm ${skipFile}`, description: 'delete skip-worktree file' },
  })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore + 1, 'skip-worktree target forces exactly one fresh snapshot')
  assert.equal(lastSnapshotPathExisted, true, 'forced snapshot observed the file still on disk')
  const rec = lastAudit()
  assert.deepEqual(rec.gitRecovery, [
    { path: skipFile, state: 'unrecoverable', unrecoverableReason: 'skip-worktree' },
  ])
  assert.ok(rec.snapshotId, 'audit records the forced snapshot id')
})

test('gate: git add -f tracked file matching ignore -> yes, no force', async () => {
  tmHealthy()
  setupRepoFiles()
  writeFileSync(join(REPO, '.env.forced'), 'forced')
  execSync(`git -C ${REPO} add -f .env.forced`)
  execSync(`git -C ${REPO} commit -qm forced`)
  applyGate()
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime4.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  const r = await gate({ name: 'bash', arguments: { command: `rm ${join(REPO, '.env.forced')}` } })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore, 'force-added tracked file must not force a snapshot')
  const rec = lastAudit()
  assert.deepEqual(rec.gitRecovery, [{ path: join(REPO, '.env.forced'), state: 'yes' }])
})

test('gate: force snapshot then normal write in window -> cooldown holds, no second snapshot', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  const ignored = join(REPO, '.env.local')
  await gate({ name: 'bash', arguments: { command: `rm ${ignored}` } })
  assert.equal(snapshotCalls, 1)
  const r = await gate({ name: 'write', arguments: { file_path: join(REPO, 'later.txt'), content: 'y' } })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, 1, 'cooldown still applies after a forced snapshot')
})

test('gate: forced snapshot FAILURE increments but write is still allowed', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  snapshotFailures = 1 // the forced snapshot errors
  const ignored = join(REPO, '.env.local')
  const r = await gate({ name: 'bash', arguments: { command: `rm ${ignored}` } })
  assert.equal(r.kind, 'allow', 'snapshot failure must never deny')
  const rec = lastAudit()
  assert.equal(rec.decision, 'allow')
  assert.deepEqual(rec.gitRecovery, [{ path: ignored, state: 'no' }])
  assert.equal(rec.snapshotId, undefined)
})

test('gate: injected commit failure downgrades untracked target to unknown (S2)', async () => {
  tmHealthy()
  setupRepoFiles()
  __setGitOverride(async (args: string[]) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return REPO
    if (args[0] === 'rev-parse' && args[1] === 'HEAD') return 'deadbeef'
    if (args[0] === 'status') return '?? fresh-untracked.txt\n'
    if (args[0] === 'add') throw new Error('simulated index lock')
    if (args.includes('commit')) throw new Error('simulated commit failure')
    return ''
  })
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') return { stdout: '', code: 1 }
    return { stdout: '', code: 1 }
  })
  applyGate()
  writeFileSync(join(REPO, 'fresh-untracked.txt'), 'u')
  const r = await gate({ name: 'write', arguments: { file_path: join(REPO, 'fresh-untracked.txt'), content: 'u2' } })
  assert.equal(r.kind, 'allow')
  const rec = lastAudit()
  const t = rec.gitRecovery?.find((g: any) => g.path.endsWith('fresh-untracked.txt'))
  assert.ok(t, 'gitRecovery must include the target')
  assert.equal(t.state, 'unknown', 'swallowed commit failure must not claim yes')
})

test('gate: delete of non-existent non-ignored path does not force and does not crash', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime5.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  const ghost = join(REPO, 'never-existed.txt')
  const r = await gate({ name: 'bash', arguments: { command: `rm ${ghost}` } })
  assert.equal(r.kind, 'allow')
  assert.equal(snapshotCalls, callsBefore, 'untracked non-ignored ghost forces nothing')
  const rec = lastAudit()
  assert.equal(rec.gitRecovery[0].state, 'unknown') // backfill miss
})

test('gate: default warnOnIgnoredDelete=false -> no warning, snapshot still forced', async () => {
  tmHealthy()
  setupRepoFiles()
  const warnings: string[] = []
  const origWarn = console.warn
  console.warn = (...a: any[]) => { warnings.push(a.join(' ')) }
  try {
    applyGate({ warnOnIgnoredDelete: false })
    await gate({ name: 'bash', arguments: { command: `rm ${join(REPO, '.env.local')}` } })
  } finally {
    console.warn = origWarn
  }
  assert.equal(snapshotCalls, 1)
  assert.ok(!warnings.some((w) => /git cannot restore|git-ignored/.test(w)), 'no ignored warning by default')
})

test('gate: warnOnIgnoredDelete=true names the no target but never denies', async () => {
  tmHealthy()
  setupRepoFiles()
  const warnings: string[] = []
  const origWarn = console.warn
  console.warn = (...a: any[]) => { warnings.push(a.join(' ')) }
  try {
    applyGate({ warnOnIgnoredDelete: true })
    const r = await gate({ name: 'bash', arguments: { command: `rm ${join(REPO, '.env.local')}` } })
    assert.equal(r.kind, 'allow')
  } finally {
    console.warn = origWarn
  }
  assert.ok(warnings.some((w) => w.includes('.env.local') && /git cannot restore|git-ignored/.test(w)))
})


test('gate: untracked non-ignored file delete -> checkpoint commits it -> yes (#3)', async () => {
  tmHealthy()
  setupRepoFiles()
  applyGate()
  const f = join(REPO, 'brand-new.txt')
  writeFileSync(f, 'fresh')
  // First gate: checkpoint commits the untracked file before the (simulated)
  // write; backfill must confirm it became tracked => yes.
  const r = await gate({ name: 'write', arguments: { file_path: f, content: 'v2' } })
  assert.equal(r.kind, 'allow')
  const rec = lastAudit()
  const t = rec.gitRecovery?.find((g: any) => g.path.endsWith('brand-new.txt'))
  assert.ok(t)
  assert.equal(t.state, 'yes', 'checkpoint committed the previously-untracked file')
})

test('gate: .gitignore bytes unchanged across an ignored-target write (#13)', async () => {
  tmHealthy()
  setupRepoFiles()
  const gi = join(REPO, '.gitignore')
  const before = readFileSync(gi)
  applyGate()
  await gate({ name: 'bash', arguments: { command: `rm ${join(REPO, '.env.local')}` } })
  const after = readFileSync(gi)
  assert.ok(before.equals(after), '.gitignore must be byte-identical')
})

test('recovery probe: batch with one fatal 128 group leaves a sibling group confirmed (#14)', async () => {
  // Two toplevels: sibling repo probes fine; fatal repo returns 128 on ls-files.
  const GOOD = '/private/tmp/ifr-good'
  const BAD = '/private/tmp/ifr-bad'
  __setGitOverride(async (args: string[], _cwd: string) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return _cwd
    return ''
  })
  __setGitProbeOverride(async (args: string[], cwd: string) => {
    if (cwd === BAD && args[0] === 'ls-files') return { stdout: '', code: 128 }
    if (cwd === GOOD && args[0] === 'ls-files') return { stdout: 'ok.txt' + String.fromCharCode(0), code: 0 }
    return { stdout: '', code: 1 }
  })
  // applyGate not needed: call the probe through the gate's git module seam is
  // enough, but route via the exported probe by a fresh import already loaded.
  const { probeGitRecovery } = await import('./src/git.ts')
  const r = await probeGitRecovery([join(GOOD, 'ok.txt'), join(BAD, 'boom.txt')])
  const good = r.find((x) => x.path.endsWith('ok.txt'))
  const bad = r.find((x) => x.path.endsWith('boom.txt'))
  assert.equal(good?.state, 'yes', 'sibling confirmed target keeps state')
  assert.equal(bad?.state, 'unknown', 'fatal 128 target -> unknown, never no')
})

test('render: tm_audit marks git=no and old JSONL without the field still renders', async () => {
  tmHealthy()
  setupRepoFiles()
  rmSync(join(ROOT, '.tm-guard'), { recursive: true, force: true })
  applyGate()
  // Hand-write an OLD-format record lacking gitRecovery.
  const oldRec = JSON.stringify({
    ts: new Date().toISOString(), tool: 'legacy', category: 'file_write',
    decision: 'allow', reason: 'old', targetPaths: ['/x/old.txt'],
  }) + '\n'
  appendFileSync(auditPath, oldRec)
  await gate({ name: 'bash', arguments: { command: `rm ${join(REPO, '.env.local')}` } })

  const auditOut: string = await findTool('tm_audit').execute({ limit: 10 })
  assert.match(auditOut, /git=no\(1\)/)
  assert.match(auditOut, /\[file_write\] legacy/)
  const legacyLine = auditOut.split('\n').find((l) => l.includes('legacy'))
  assert.ok(legacyLine && !legacyLine.includes('git=no'))

  const statusOut: string = await findTool('tm_status').execute({})
  assert.match(statusOut, /git-unrecoverable targets in recent window: 1/)
  assert.match(statusOut, /git=no\(1\)/)
})

test('gate: failed checkpoint in cooldown forces one fresh snapshot, observes pre-write file, downgrades yes->unknown (B1/M1)', async () => {
  setupRepoFiles()
  const tracked = join(REPO, 'tracked.txt')
  const beforeBytes = readFileSync(tracked, 'utf8')
  let snapshotSawFile: boolean | null = null
  tmHealthy(() => {
    snapshotCalls++
    snapshotSawFile = existsSync(tracked) && readFileSync(tracked, 'utf8') === beforeBytes
    snapSeq++
    return { stdout: `Created local snapshot with date: 2026-10-20-16${String(snapSeq).padStart(4, '0')}\n` }
  })
  // Baseline establishes and reports HEAD, but the pre-write checkpoint's
  // `git add -A` / commit fails (locked index) -> checkpointFailed = true.
  __setGitOverride(async (args: string[]) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return REPO
    if (args[0] === 'rev-parse' && args[1] === 'HEAD') return 'deadbeef'
    if (args[0] === 'status') return ' M tracked.txt\n'
    if (args[0] === 'add' || args[0] === 'commit') throw new Error('simulated index lock')
    return ''
  })
  applyGate()
  // Prime write opens the 300s cooldown window; its own checkpoint succeeds.
  await gate({ name: 'write', arguments: { file_path: join(REPO, 'prime-b1.txt'), content: 'x' } })
  const callsBefore = snapshotCalls
  const r = await gate({
    name: 'write',
    arguments: { file_path: tracked, content: 'NEW-BYTES' },
  })
  assert.equal(r.kind, 'allow', 'checkpoint failure never denies the write')
  assert.equal(snapshotCalls, callsBefore + 1, 'failed checkpoint forces exactly one fresh snapshot inside cooldown')
  assert.equal(snapshotSawFile, true, 'forced snapshot observed the pre-write file before next()')
  const rec = lastAudit()
  const t = (rec.gitRecovery ?? []).find((g: any) => g.path === tracked)
  assert.ok(t, 'gitRecovery lists the tracked target')
  assert.equal(t.state, 'unknown', 'swallowed checkpoint failure must not claim yes')
  assert.ok(rec.snapshotId, 'audit records the forced snapshot id')
})
