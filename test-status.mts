// U-08: tm_status structured layered output.
//
// tm_status is the only entry point a user reaches for when something looks
// wrong, and the pre-U-08 output was 20 flat lines interleaving policy echo
// with health faults — a reader who saw UNHEALTHY had no idea what to do next.
// These tests pin the two properties that fix that:
//
//   (a) the four section titles always exist, in order (stable anchors);
//   (b) when something is unhealthy, the fault is at the TOP of Health and
//       carries an executable next-step command — never a bare verdict.
//
// Two scenarios are mocked (healthy / unhealthy), plus the limited-mode host.
// Rendering is a pure function of already-gathered facts, so these run without
// touching tmutil; the integration path (real tool invocation) is covered too,
// to prove index.ts actually routes through the new renderer.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import {
  renderStatusReport,
  formatBytes,
  RECENT_STATUS_ITEMS,
  type StatusInput,
  type StatusConfigView,
} from './src/status.ts'
import { AuditLog } from './src/audit.ts'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'

let ROOT = ''
let ORIG_CWD = ''
let seq = 0

/** Isolated workspace per test: audit log + reports live inside ROOT. */
function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), `tm-status-${seq++}-`))
  mkdirSync(join(dir, '.tm-guard'), { recursive: true })
  return dir
}

const CONFIG: StatusConfigView = {
  protectedPaths: ['/protected/one', '/protected/two'],
  denyReadPaths: ['~/.ssh', '~/.aws', '~/.gnupg'],
  denyNetwork: true,
  denySystem: true,
  failClosed: true,
  requireTaskSnapshot: true,
  autoApprove: true,
  snapshotCooldownSeconds: 30,
}

/** Healthy TM fixture: every check passes. */
function healthyInput(overrides: Partial<StatusInput> = {}): StatusInput {
  const dir = workspace()
  return {
    platformSupported: true,
    platform: 'darwin',
    health: {
      healthy: true,
      destinationConfigured: true,
      hasSnapshots: true,
      snapshotCount: 12,
      workspaceProtected: true,
      unprotectedPaths: [],
      issues: [],
      checkedAt: new Date('2026-10-06T05:00:00Z'),
    },
    status: {
      destinationConfigured: true,
      raw: 'Name : SD',
      hasLocalSnapshots: true,
      snapshotCount: 12,
    },
    latest: {
      name: 'com.apple.TimeMachine.2026-10-06-050000.local',
      date: '2026-10-06-050000',
      createdAt: new Date('2026-10-06T05:00:00Z'),
    },
    config: CONFIG,
    audit: new AuditLog(dir),
    auditCount: 0,
    writeCount: 0,
    recentDecisions: [],
    ...overrides,
  }
}

/** Unhealthy TM fixture: destination missing, no snapshots, workspace excluded. */
function unhealthyInput(overrides: Partial<StatusInput> = {}): StatusInput {
  const dir = workspace()
  const issues = [
    'Time Machine backup destination is NOT configured',
    'No local Time Machine snapshots exist (nothing to roll back to)',
    'Workspace paths NOT protected by Time Machine: /protected/one, /protected/two',
  ]
  return {
    platformSupported: true,
    platform: 'darwin',
    health: {
      healthy: false,
      destinationConfigured: false,
      hasSnapshots: false,
      snapshotCount: 0,
      workspaceProtected: false,
      unprotectedPaths: ['/protected/one', '/protected/two'],
      issues,
      checkedAt: new Date('2026-10-06T05:00:00Z'),
    },
    status: {
      destinationConfigured: false,
      raw: '',
      hasLocalSnapshots: false,
      snapshotCount: 0,
    },
    latest: null,
    config: CONFIG,
    audit: new AuditLog(dir),
    auditCount: 0,
    writeCount: 0,
    recentDecisions: [],
    ...overrides,
  }
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = workspace()
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  process.chdir(ORIG_CWD)
})

/* ------------------------------------------------------------------ */
/* (a) Four-section structure                                          */
/* ------------------------------------------------------------------ */

test('U-08: four section titles exist and appear in order', () => {
  const out = renderStatusReport(healthyInput())
  for (const title of ['【Health】', '【Policy】', '【Data sources】', '【Recent】']) {
    assert.ok(out.includes(title), `missing section ${title}`)
  }
  const order = ['【Health】', '【Policy】', '【Data sources】', '【Recent】'].map((t) =>
    out.indexOf(t),
  )
  assert.deepEqual(
    order,
    [...order].sort((a, b) => a - b),
    'sections must appear in Health → Policy → Data sources → Recent order',
  )
  // The legacy header stays: pre-U-08 callers and tests grep for it.
  assert.match(out, /=== TM-Guard Status ===/)
})

test('U-08: healthy scenario renders HEALTHY and no fault lines', () => {
  const out = renderStatusReport(healthyInput())
  assert.match(out, /✅ HEALTHY/)
  assert.match(out, /HEALTHY ✅/)
  assert.doesNotMatch(out, /🚫 UNHEALTHY/)
  assert.doesNotMatch(out, /→ next:/)
  assert.match(out, /Fail-closed\s*: YES/)
})

/* ------------------------------------------------------------------ */
/* (b) Faults first, each with a next step                             */
/* ------------------------------------------------------------------ */

test('U-08: unhealthy faults are placed at the TOP of the Health section', () => {
  const out = renderStatusReport(unhealthyInput())
  const healthAt = out.indexOf('【Health】')
  const policyAt = out.indexOf('【Policy】')
  const healthBody = out.slice(healthAt, policyAt)

  const unhealthyAt = healthBody.indexOf('🚫 UNHEALTHY')
  assert.ok(unhealthyAt >= 0, 'unhealthy verdict must be present')

  // The fault block must precede the qualifying fact lines inside Health, so
  // the very first thing read is what is broken — not a snapshot count.
  assert.ok(
    unhealthyAt < healthBody.indexOf('Workspace protected'),
    'fault block must be above the qualifying details',
  )
  assert.ok(
    unhealthyAt < healthBody.indexOf('Local snapshots'),
    'fault block must be above the qualifying details',
  )
  // And Health must still come before every other section.
  assert.ok(healthAt < policyAt && healthAt < out.indexOf('【Data sources】'))
})

test('U-08: every fault carries an executable next-step command', () => {
  const out = renderStatusReport(unhealthyInput())
  const healthBody = out.slice(out.indexOf('【Health】'), out.indexOf('【Policy】'))

  const faults = healthBody.split('\n').filter((l) => /^\s+\d+\.\s/.test(l))
  const nexts = healthBody.split('\n').filter((l) => l.includes('→ next:'))
  assert.equal(faults.length, 3, `expected 3 faults, got:\n${healthBody}`)
  assert.equal(
    nexts.length,
    faults.length,
    'each fault must be paired with exactly one next step',
  )
  // The remedies must name concrete, runnable actions.
  assert.match(out, /tm_snapshot|tm_backup/)
  assert.match(out, /tmutil destinationinfo/)
  assert.match(out, /Time Machine/)
})

test('U-08: fault ordering puts the blocking root cause first', () => {
  const out = renderStatusReport(unhealthyInput())
  const healthBody = out.slice(out.indexOf('【Health】'), out.indexOf('【Policy】'))
  const firstFault = healthBody.split('\n').find((l) => /^\s+1\.\s/.test(l))!
  assert.match(
    firstFault,
    /destination is NOT configured/,
    'the destination is the root cause and must be fault #1',
  )
})

test('U-08: no blocking fault when healthy — degraded hints never claim UNHEALTHY', () => {
  const out = renderStatusReport(healthyInput())
  const healthBody = out.slice(out.indexOf('【Health】'), out.indexOf('【Policy】'))
  assert.doesNotMatch(healthBody, /🚫/)
  assert.match(healthBody, /Time Machine is a working rollback net/)
})

/* ------------------------------------------------------------------ */
/* (2) Policy summary                                                  */
/* ------------------------------------------------------------------ */

test('U-08: Policy section summarizes effective policy counts and switches', () => {
  const out = renderStatusReport(healthyInput())
  const policy = out.slice(out.indexOf('【Policy】'), out.indexOf('【Data sources】'))
  assert.match(policy, /denyReadPaths\s*:\s*3 path\(s\)/)
  assert.match(policy, /denyNetwork\s*: YES/)
  assert.match(policy, /denySystem\s*: YES/)
  assert.match(policy, /Fail-closed\s*: YES/)
  assert.match(policy, /autoApprove\s*: YES/)
  assert.match(policy, /Require task snapshot\s*: YES/)
  assert.match(policy, /\/protected\/one/)
  assert.match(policy, /snapshotCooldown\s*: 30s/)
})

test('U-08: Policy reflects a permissive config without misreporting it', () => {
  const permissive: StatusConfigView = {
    ...CONFIG,
    denyReadPaths: [],
    denyNetwork: false,
    denySystem: false,
    failClosed: false,
    autoApprove: false,
  }
  const out = renderStatusReport(healthyInput({ config: permissive }))
  const policy = out.slice(out.indexOf('【Policy】'), out.indexOf('【Data sources】'))
  assert.match(policy, /denyReadPaths\s*:\s*0 path\(s\)/)
  assert.match(policy, /deliberate opt-out/)
  assert.match(policy, /denyNetwork\s*: no — allowed/)
  assert.match(policy, /denySystem\s*: no — allowed/)
  assert.match(policy, /Fail-closed\s*: no/)
  assert.match(policy, /autoApprove\s*:\s*no/)
})

/* ------------------------------------------------------------------ */
/* (3) Data sources — read-only measurement                            */
/* ------------------------------------------------------------------ */

test('U-08: Data sources reports audit size, rotation generations, reports, .git', () => {
  const dir = workspace()
  const audit = new AuditLog(dir)
  writeFileSync(audit.path, '{"ts":"t"}\n'.repeat(50), 'utf8')
  appendFileSync(`${audit.path}.1`, 'older\n', 'utf8')
  appendFileSync(`${audit.path}.2`, 'oldest\n', 'utf8')
  mkdirSync(join(dir, 'reports'), { recursive: true })
  writeFileSync(join(dir, 'reports', 'turn-a.md'), 'x', 'utf8')
  writeFileSync(join(dir, 'reports', 'turn-b.md'), 'x', 'utf8')

  const out = renderStatusReport(
    healthyInput({ audit, auditCount: 60, writeCount: 7 }),
  )
  const data = out.slice(out.indexOf('【Data sources】'), out.indexOf('【Recent】'))
  assert.match(data, /audit\.jsonl\s*:\s*\d+(\.\d+)?\s*[BKMGT]i?B/)
  assert.match(data, /2 rotation generation\(s\)/)
  assert.match(data, /\.1, \.2/)
  assert.match(data, /60 records across generations \(7 write ops\)/)
  assert.match(data, /reports\/\s*:\s*2 file\(s\)/)
  assert.match(data, /\.git\s*:/)
})

test('U-08: Data sources degrades gracefully when nothing exists yet', () => {
  const out = renderStatusReport(healthyInput())
  const data = out.slice(out.indexOf('【Data sources】'), out.indexOf('【Recent】'))
  assert.match(data, /audit\.jsonl\s*:\s*absent/)
  assert.match(data, /0 rotation generation\(s\)/)
  assert.match(data, /reports\/\s*:\s*absent/)
  assert.match(data, /\.git\s*:\s*absent/)
})

test('U-08: formatBytes is deterministic and unit-correct', () => {
  assert.equal(formatBytes(0), '0 B')
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(1024), '1.0 KiB')
  assert.equal(formatBytes(1536), '1.5 KiB')
  assert.equal(formatBytes(20 * 1024), '20 KiB')
  assert.equal(formatBytes(1024 * 1024), '1.0 MiB')
  assert.equal(formatBytes(-1), 'unknown')
  assert.equal(formatBytes(Number.NaN), 'unknown')
})

/* ------------------------------------------------------------------ */
/* (4) Recent decisions                                                */
/* ------------------------------------------------------------------ */

test('U-08: Recent shows ts + tool + category + decision, newest first', () => {
  const records = [
    { ts: '2026-10-06T05:00:01.000Z', tool: 'Write', category: 'file_write', decision: 'allow' as const, reason: '', targetPaths: [] },
    { ts: '2026-10-06T05:00:02.000Z', tool: 'bash', category: 'network', decision: 'deny' as const, reason: '', targetPaths: [] },
  ]
  const out = renderStatusReport(healthyInput({ recentDecisions: records }))
  const recent = out.slice(out.indexOf('【Recent】'))
  assert.match(recent, /2026-10-06T05:00:01\.000Z\s+ALLOW \[file_write\] Write/)
  assert.match(recent, /2026-10-06T05:00:02\.000Z\s+DENY\s+\[network\] bash/)
  assert.ok(
    recent.indexOf('05:00:02') < recent.indexOf('05:00:01'),
    'newest decision must be listed first',
  )
})

test('U-08: Recent handles an empty audit log without an empty section', () => {
  const out = renderStatusReport(healthyInput())
  const recent = out.slice(out.indexOf('【Recent】'))
  assert.match(recent, /\(none recorded yet\)/)
  assert.match(recent, new RegExp(`last ${RECENT_STATUS_ITEMS} audit decision`))
})

/* ------------------------------------------------------------------ */
/* (3+) Platform-limited host (U-19 interaction)                       */
/* ------------------------------------------------------------------ */

test('U-08: limited mode is flagged in Health and reports no TM fault', () => {
  const out = renderStatusReport(
    unhealthyInput({
      platformSupported: false,
      platform: 'linux',
      health: {
        healthy: false,
        destinationConfigured: false,
        hasSnapshots: false,
        snapshotCount: 0,
        workspaceProtected: false,
        unprotectedPaths: [],
        issues: [],
        checkedAt: new Date('2026-10-06T05:00:00Z'),
      },
    }),
  )
  const healthBody = out.slice(out.indexOf('【Health】'), out.indexOf('【Policy】'))
  assert.match(healthBody, /limited mode — linux has no Time Machine/)
  assert.match(healthBody, /git baseline only/)
  assert.match(healthBody, /N\/A — no TM on this platform/)
  // TM is absent, not broken: no fixable fault may be advertised (U-19).
  assert.doesNotMatch(healthBody, /🚫 UNHEALTHY/)
  assert.doesNotMatch(healthBody, /→ next:/)
  assert.match(out, /Platform\s*:\s*linux — limited mode \(no TM\)/)
})

/* ------------------------------------------------------------------ */
/* Integration: the registered tool routes through this renderer        */
/* ------------------------------------------------------------------ */

test('U-08: tm_status tool emits the four sections end-to-end', async () => {
  const dir = workspace()
  process.chdir(dir)
  execSync(`git init -q ${dir}/repo`)
  __setExecOverride(async (_f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-06-050000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    throw new Error(`unexpected ${_f} ${a.join(' ')}`)
  })
  const registered: any[] = []
  const ctx = {
    on() { return this },
    tools: { register(t: any) { registered.push(t) } },
    systemPrompt: { section() {} },
    inject() {},
  }
  try {
    apply(ctx as any, { protectedPaths: [dir] })
    const tool = registered.find((t) => t.name === 'tm_status')
    assert.ok(tool, 'tm_status must be registered')
    const out: string = await tool.execute({})
    for (const title of ['【Health】', '【Policy】', '【Data sources】', '【Recent】']) {
      assert.ok(out.includes(title), `tool output missing ${title}`)
    }
    assert.match(out, /HEALTHY/)
    assert.match(out, /Fail-closed\s*: YES/)
  } finally {
    __setExecOverride(null)
    process.chdir(ROOT)
  }
})

test('U-08: tm_status tool surfaces faults with next steps when TM is broken', async () => {
  const dir = workspace()
  process.chdir(dir)
  __setExecOverride(async () => {
    throw new Error('tmutil: Full Disk Access required')
  })
  const registered: any[] = []
  const ctx = {
    on() { return this },
    tools: { register(t: any) { registered.push(t) } },
    systemPrompt: { section() {} },
    inject() {},
  }
  try {
    apply(ctx as any, { protectedPaths: [dir] })
    const out: string = await registered.find((t) => t.name === 'tm_status').execute({})
    assert.match(out, /UNHEALTHY/)
    assert.match(out, /⚠️/)
    assert.match(out, /→ next:/)
    const healthBody = out.slice(out.indexOf('【Health】'), out.indexOf('【Policy】'))
    assert.ok(
      healthBody.indexOf('UNHEALTHY') < healthBody.indexOf('Workspace protected'),
      'faults must be at the top of Health',
    )
  } finally {
    __setExecOverride(null)
    process.chdir(ROOT)
  }
})
