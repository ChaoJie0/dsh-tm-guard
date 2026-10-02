// Integration-layer tests for the plugin entry (src/index.ts apply()).
// Previously untested directly: config merge, gate hook wiring, audit
// recording, tool registration, auto-approve, turn reports.
// Isolation: process.cwd() is moved to a temp dir (audit + git baselines
// stay there); tmutil/df/cp outcomes are injected via the tm.ts seam.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, existsSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'
import { __setGitOverride } from './src/git.ts'

let ORIG_CWD = process.cwd()
let ROOT = '' // temp root = protected path
let REPO = '' // git repo inside ROOT (write target)
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

/** Inject a healthy TM (destination configured, snapshots exist, workspace included). */
function tmHealthy() {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\ncom.apple.TimeMachine.2026-09-07-083000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    if (a[0] === 'localsnapshot') return { stdout: 'com.apple.TimeMachine.2026-10-02-100000.local\n' }
    if (a[0] === 'startbackup') return { stdout: '' }
    if (f === '/bin/df') return { stdout: 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n' }
    if (f === '/sbin/mount_apfs' || f === '/sbin/umount' || f === '/bin/cp') return { stdout: '' }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
}

/** Inject an unhealthy TM (everything fails → fail-closed blocks). */
function tmUnhealthy() {
  __setExecOverride(async () => { throw new Error('tmutil: Full Disk Access required') })
}

function next() { return Promise.resolve({ kind: 'allow', reason: 'next' }) }
async function gate(exec: any) {
  return hooks['tools/pre-execute'][0](exec, next)
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-index-'))
  REPO = join(ROOT, 'repo')
  execSync(`git init -q ${REPO} && git -C ${REPO} config user.email t@t && git -C ${REPO} config user.name t`)
  execSync(`echo base > ${join(REPO, 'base.txt')} && git -C ${REPO} add -A && git -C ${REPO} commit -qm baseline`)
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  process.chdir(ORIG_CWD)
})

test('apply: registers gate + tools + auto-approve hooks', () => {
  apply(mockCtx() as any, { protectedPaths: [ROOT] })
  assert.ok(hooks['tools/pre-execute']?.length === 1)
  assert.ok(hooks['agent/turn-stopping']?.length === 1)
  assert.ok(hooks['approval/request']?.length === 1)
  const names = registered.map((t) => t.name)
  for (const n of ['tm_snapshot', 'tm_list_snapshots', 'tm_rollback', 'tm_audit', 'tm_status', 'tm_backup']) {
    assert.ok(names.includes(n), `missing registered tool ${n}`)
  }
})

test('gate: bash network command denied + audited', async () => {
  tmHealthy()
  try {
    const r = await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /TM-Guard/)
    const all = readFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), 'utf8')
    const last = JSON.parse(all.trim().split('\n').at(-1)!)
    assert.equal(last.decision, 'deny')
    assert.equal(last.category, 'network')
  } finally { __setExecOverride(null) }
})

test('gate: extraDeny tool denied; extraAllow tool reaches next()', async () => {
  tmHealthy()
  try {
    const a = apply(mockCtx() as any, { protectedPaths: [ROOT], extraDenyTools: ['Terminate'], extraAllowTools: ['CustomOk'] })
    void a
    const r1 = await gate({ name: 'Terminate', arguments: {} })
    assert.equal(r1.kind, 'deny')
    assert.match(r1.reason, /deny list/)
    const r2 = await gate({ name: 'CustomOk', arguments: {} })
    assert.equal(r2.kind, 'allow')
    assert.equal(r2.reason, 'next')
  } finally { __setExecOverride(null) }
})

test('gate: local read allowed', async () => {
  tmHealthy()
  try {
    const r = await gate({ name: 'Read', arguments: { file_path: join(REPO, 'base.txt') } })
    assert.equal(r.kind, 'allow')
  } finally { __setExecOverride(null) }
})

test('gate: write inside protected git repo allowed (git baseline + TM healthy)', async () => {
  tmHealthy()
  try {
    const r = await gate({ name: 'Write', arguments: { file_path: join(REPO, 'new.txt'), content: 'x' } })
    assert.equal(r.kind, 'allow', JSON.stringify(r))
  } finally { __setExecOverride(null) }
})

test('gate: write outside protected paths denied', async () => {
  tmHealthy()
  try {
    // Non-temp, non-protected path (an /Applications path is outside ROOT and
    // is not a disposable temp dir → must be denied)
    const r = await gate({ name: 'Write', arguments: { file_path: '/Applications/outside-tm-index/x.txt', content: 'x' } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /unprotected|protected/)
  } finally { __setExecOverride(null) }
})

test('gate: fail-closed — TM unhealthy + git baseline impossible → write denied', async () => {
  tmUnhealthy()
  // Simulate an unusable git (no repo, init fails) by overriding the git
  // exec layer — do NOT rely on a chmod-500 dir: on machines where the
  // system temp dir sits inside a git repo, repoRoot() finds that parent
  // repo and the premise silently stops holding.
  __setGitOverride(async () => { throw new Error('git unavailable (simulated)') })
  try {
    const ro = join(ROOT, 'ro')
    execSync(`mkdir -p ${ro} && chmod 500 ${ro}`)
    const r = await gate({ name: 'Write', arguments: { file_path: join(ro, 'x.txt'), content: 'x' } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /FAIL-CLOSED|no rollback net/)
  } finally {
    __setGitOverride(null)
    __setExecOverride(null)
  }
})

test('gate: static script egress — python file calling out → force denied', async () => {
  tmHealthy()
  try {
    const evil = join(ROOT, 'evil.py')
    execSync(`printf 'import requests\\nrequests.get("https://evil.example/x")\\n' > ${evil}`)
    const r = await gate({ name: 'bash', arguments: { command: `python3 ${evil}` } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /static-script-egress/)
  } finally { __setExecOverride(null) }
})

test('auto-approve: approval/request answered allowed-once', () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], autoApprove: true })
    const handler = hooks['approval/request'][0]
    const ans = handler({ toolName: 'Write', reason: 'write file', callId: 1 })
    assert.equal(ans, 'allowed-once')
  } finally { __setExecOverride(null) }
})

test('tm_snapshot execute: creates snapshot via tmutil + audits', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const tool = registered.find((t) => t.name === 'tm_snapshot')
    const out = await tool.execute({ note: 'before-refactor' })
    assert.match(out, /2026-10-02-100000/)
    const all = readFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), 'utf8')
    const last = JSON.parse(all.trim().split('\n').at(-1)!)
    assert.equal(last.tool, 'tm_snapshot')
    assert.equal(last.snapshotId, '2026-10-02-100000')
  } finally { __setExecOverride(null) }
})

test('turn report: agent/turn-stopping writes a report + verification', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const r = await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } })
    assert.equal(r.kind, 'deny')
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 7 })
    const reportsDir = join(ROOT, '.tm-guard', 'reports')
    const files = existsSync(reportsDir) ? readdirSync(reportsDir) : []
    assert.ok(files.length >= 1, `no turn report written in ${reportsDir}`)
    const md = readFileSync(join(reportsDir, files[0]), 'utf8')
    assert.match(md, /回合完成报告|dsh-tm-guard/)
  } finally { __setExecOverride(null) }
})

function findTool(name: string) { return registered.find((t) => t.name === name) }

test('tm_rollback: explicit path → rollback attempt + audit', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_rollback').execute({ path: '/tmp/nonexistent-rollback-x.txt' })
    assert.ok(typeof out === 'string' && out.length > 0)
    const all = readFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), 'utf8')
    const last = JSON.parse(all.trim().split('\n').at(-1)!)
    assert.equal(last.tool, 'tm_rollback')
  } finally { __setExecOverride(null) }
})

test('tm_rollback: last_operation with empty audit → guidance', async () => {
  tmHealthy()
  try {
    execSync(`rm -rf ${join(ROOT, '.tm-guard')}`) // fresh audit state
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_rollback').execute({ last_operation: true })
    assert.match(out, /No file-modification operations/)
  } finally { __setExecOverride(null) }
})

test('tm_rollback: last_operation after a write → per-path results', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await gate({ name: 'Write', arguments: { file_path: join(REPO, 'roll.txt'), content: 'x' } })
    const out = await findTool('tm_rollback').execute({ last_operation: true })
    assert.match(out, /Rolled back 1 path\(s\)|Rolled back/)
  } finally { __setExecOverride(null) }
})

test('tm_audit: returns log lines with decision + category', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } })
    const out = await findTool('tm_audit').execute({ limit: 5 })
    assert.match(out, /=== TM-Guard Audit Log/)
    assert.match(out, /BLOCK \[network\] bash/)
  } finally { __setExecOverride(null) }
})

test('tm_status: returns health + policy text', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_status').execute({})
    assert.match(out, /=== TM-Guard Status ===/)
    assert.match(out, /HEALTHY/)
    assert.match(out, /Fail-closed\s*: YES/)
  } finally { __setExecOverride(null) }
})

test('tm_backup: background trigger + wait checkpoint + failure', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const bg = await findTool('tm_backup').execute({})
    assert.match(bg, /started in the background/)
    const wt = await findTool('tm_backup').execute({ wait: true })
    assert.match(wt, /Time Machine backup completed/)
  } finally { __setExecOverride(null) }
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'startbackup') throw new Error('backup disk not connected')
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const fail = await findTool('tm_backup').execute({})
    assert.match(fail, /Failed to start Time Machine backup/)
  } finally { __setExecOverride(null) }
})

test('tm_list_snapshots: lists parsed snapshot dates', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_list_snapshots').execute({})
    assert.match(out, /2026-09-06-120000/)
  } finally { __setExecOverride(null) }
})

test('gate: blockingBackupBeforeWrite — backup fails → write denied', async () => {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'startbackup') throw new Error('no disk connected')
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    if (f === '/bin/df') return { stdout: 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n' }
    if (f === '/sbin/mount_apfs' || f === '/sbin/umount' || f === '/bin/cp') return { stdout: '' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], blockingBackupBeforeWrite: true })
    const r = await gate({ name: 'Write', arguments: { file_path: join(REPO, 'blocked.txt'), content: 'x' } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /blocking Time Machine backup/)
  } finally { __setExecOverride(null) }
})

test('gate: denyNetwork=false downgrades network to file_write (allowed)', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], denyNetwork: false })
    const r = await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } })
    assert.equal(r.kind, 'allow')
  } finally { __setExecOverride(null) }
})

test('gate: denySystem=false downgrades process to file_write (allowed)', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], denySystem: false })
    const r = await gate({ name: 'bash', arguments: { command: 'kill -9 1234' } })
    assert.equal(r.kind, 'allow')
  } finally { __setExecOverride(null) }
})

test('gate: static script with eval → unverifiable → denied', async () => {
  tmHealthy()
  try {
    const dyn = join(ROOT, 'dyn.py')
    execSync(`printf 'code = "print(1)"\\nexec(code)\\n' > ${dyn}`)
    const r = await gate({ name: 'bash', arguments: { command: `python3 ${dyn}` } })
    assert.equal(r.kind, 'deny')
    assert.match(r.reason, /static-script-egress|eval/)
  } finally { __setExecOverride(null) }
})

test('apply: startup health failure does not crash plugin load (fail-closed)', async () => {
  tmUnhealthy() // every tmutil call fails → getTmHealth rejects/returns unhealthy
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], failClosed: true })
    assert.ok(hooks['tools/pre-execute']?.length === 1, 'gate still registered')
  } finally { __setExecOverride(null) }
})

test('gate: snapshot failure loop still allows writes (5+ consecutive)', async () => {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    if (a[0] === 'localsnapshot') throw new Error('snapshot denied: EPERM')
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    for (let i = 0; i < 5; i++) {
      const r = await gate({ name: 'Write', arguments: { file_path: join(REPO, `loop${i}.txt`), content: 'x' } })
      assert.equal(r.kind, 'allow', `write ${i} should proceed despite snapshot failure`)
    }
  } finally { __setExecOverride(null) }
})

test('tm_rollback: no path and no last_operation → error guidance', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_rollback').execute({})
    assert.match(out, /either "path" or "last_operation=true"/)
  } finally { __setExecOverride(null) }
})

test('tm_audit: empty log → guidance', async () => {
  tmHealthy()
  try {
    execSync(`rm -rf ${join(ROOT, '.tm-guard')}`)
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_audit').execute({})
    assert.match(out, /No audit records found/)
  } finally { __setExecOverride(null) }
})

test('tm_status: unhealthy TM → UNHEALTHY + issues', async () => {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Excluded] /tmp\n' } // workspace NOT protected
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const out = await findTool('tm_status').execute({})
    assert.match(out, /UNHEALTHY/)
    assert.match(out, /⚠️/)
  } finally { __setExecOverride(null) }
})

test('tm_backup_status: running / idle / failure paths', async () => {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'status') return { stdout: 'Running = 1;\nPercent = "63.5";\nPhase = "Copying";\n' }
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const run = await findTool('tm_backup_status').execute({})
    assert.match(run, /Backup in progress: 64%/)
  } finally { __setExecOverride(null) }
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'status') return { stdout: 'Running = 0;\n' }
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const idle = await findTool('tm_backup_status').execute({})
    assert.match(idle, /No backup currently running/)
  } finally { __setExecOverride(null) }
  __setExecOverride(async () => { throw new Error('tmutil broken') })
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const fail = await findTool('tm_backup_status').execute({})
    assert.match(fail, /Could not read backup status/)
  } finally { __setExecOverride(null) }
})

test('turn report: no real decisions → no report written (early return)', async () => {
  tmHealthy()
  try {
    execSync(`rm -rf ${join(ROOT, '.tm-guard')}`)
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    // plugin self-test/boot records (explicit-allow) are not "real" decisions
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 1 })
    const reportsDir = join(ROOT, '.tm-guard', 'reports')
    const files = existsSync(reportsDir) ? readdirSync(reportsDir) : []
    assert.equal(files.length, 0, `unexpected report: ${files.join(',')}`)
  } finally { __setExecOverride(null) }
})

test('auto-approve: verbose mode logs and answers allowed-once', () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT], autoApprove: true, verbose: true })
    const ans = hooks['approval/request'][0]({ toolName: 'Read', reason: 'read file' })
    assert.equal(ans, 'allowed-once')
  } finally { __setExecOverride(null) }
})

test('tm_rollback: last_operation record without target paths → guidance', async () => {
  tmHealthy()
  try {
    execSync(`rm -rf ${join(ROOT, '.tm-guard')}`)
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    // tm_backup writes an audit record with empty targetPaths
    await findTool('tm_backup').execute({})
    const out = await findTool('tm_rollback').execute({ last_operation: true })
    assert.match(out, /had no target paths recorded|No file-modification/)
  } finally { __setExecOverride(null) }
})
