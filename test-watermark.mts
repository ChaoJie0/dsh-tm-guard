// U-03 regression: the turn reporter used an array index (`readAll().length`)
// to remember how far it had reported. Rotation/trimming shrinks that array,
// so `slice(idx)` returned [] — the turn was silently skipped — and the index
// was then rewritten to the smaller length, making later turns re-report
// records that had already been reported.
//
// The fix is a durable `(ts, tool)` watermark persisted in
// `.tm-guard/state.json`. These tests drive the real `agent/turn-stopping`
// handler so the wiring (not just the pure helper) is covered.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, DEFAULT_CONFIG } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'
import { readState, resolveWatermark, watermarkOf } from './src/state.ts'
import type { AuditRecord } from './src/audit.ts'

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

/** Healthy TM so the gate allows/denies on classification, not fail-closed. */
function tmHealthy() {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    if (a[0] === 'localsnapshot') return { stdout: 'com.apple.TimeMachine.2026-10-02-100000.local\n' }
    if (f === '/bin/df') return { stdout: 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n' }
    if (f === '/bin/cp' || f === '/sbin/mount_apfs' || f === '/sbin/umount') return { stdout: '' }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
}

const auditPath = () => join(ROOT, '.tm-guard', 'audit.jsonl')
const reportsDir = () => join(ROOT, '.tm-guard', 'reports')
const statePath = () => join(ROOT, '.tm-guard', 'state.json')

/** Write a synthetic audit log (one JSON object per line). */
function writeAudit(records: AuditRecord[]) {
  mkdirSync(join(ROOT, '.tm-guard', 'reports'), { recursive: true })
  writeFileSync(auditPath(), records.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8')
}

let seq = 0
function rec(opts: Partial<AuditRecord> = {}): AuditRecord {
  seq++
  return {
    ts: `2026-03-01T10:00:${String(seq % 60).padStart(2, '0')}.${String(seq).padStart(3, '0')}Z`,
    tool: 'bash',
    category: 'read',
    decision: 'allow',
    reason: 'synthetic',
    targetPaths: [],
    ...opts,
  }
}

/** Per-turn report files written by the handler (ignore anything else). */
function turnFiles(): string[] {
  return existsSync(reportsDir()) ? readdirSync(reportsDir()).filter((f) => f.startsWith('turn-')) : []
}

/** Run the turn-stopping handler and return the report body it wrote. */
async function runTurn(turn: number): Promise<string> {
  await hooks['agent/turn-stopping'][0]({ agent: {}, turn })
  const files = turnFiles().sort()
  const newest = files[files.length - 1]
  return newest ? readFileSync(join(reportsDir(), newest), 'utf8') : ''
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-watermark-'))
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  process.chdir(ORIG_CWD)
})

beforeEach(() => {
  seq = 0
  rmSync(join(ROOT, '.tm-guard'), { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// Pure watermark semantics
// ---------------------------------------------------------------------------

test('U-03: resolveWatermark returns records strictly after the watermark', () => {
  const all = [rec(), rec(), rec(), rec()]
  const wm = watermarkOf(all.slice(0, 2))
  const { activity, index, watermarkLost } = resolveWatermark(all, wm)
  assert.equal(watermarkLost, false)
  assert.equal(index, 1)
  assert.equal(activity.length, 2)
  assert.equal(activity[0].ts, all[2].ts)
})

test('U-03: null watermark (first run) reports everything', () => {
  const all = [rec(), rec()]
  const { activity, watermarkLost } = resolveWatermark(all, null)
  assert.equal(activity.length, 2)
  assert.equal(watermarkLost, false)
})

test('U-03: rotated-away watermark degrades to all-visible + watermarkLost', () => {
  const all = [rec(), rec(), rec()]
  const wm = { ts: '1999-01-01T00:00:00.000Z', tool: 'gone' }
  const { activity, watermarkLost } = resolveWatermark(all, wm)
  assert.equal(watermarkLost, true, 'must flag the bounded duplicate risk')
  assert.equal(activity.length, 3, 'must not silently skip everything')
})

test('U-03: duplicate (ts, tool) resolves to the LAST occurrence, not the first', () => {
  const a = rec({ ts: '2026-03-01T10:00:00.000Z', tool: 'bash' })
  const b = rec({ ts: '2026-03-01T10:00:00.000Z', tool: 'bash' })
  const c = rec({ ts: '2026-03-01T10:00:01.000Z', tool: 'bash' })
  const { activity } = resolveWatermark([a, b, c], { ts: a.ts, tool: a.tool })
  assert.equal(activity.length, 1, 'taking the first match would re-report b')
  assert.equal(activity[0].ts, c.ts)
})

// ---------------------------------------------------------------------------
// Handler-level: no silent skip, no duplicate, survives rotation
// ---------------------------------------------------------------------------

test('U-03: watermark persists to state.json after a report', async () => {
  tmHealthy()
  try {
    writeAudit([rec({ tool: 'bash' }), rec({ tool: 'edit' })])
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await runTurn(1)

    assert.ok(existsSync(statePath()), 'state.json must be created')
    const st = readState(join(ROOT, '.tm-guard'))
    assert.ok(st.reportWatermark, 'watermark must be recorded')
    assert.equal(typeof st.reportWatermark!.ts, 'string')
    assert.equal(typeof st.reportWatermark!.tool, 'string')
  } finally { __setExecOverride(null) }
})

test('U-03: a turn with no NEW records does not duplicate the previous report', async () => {
  tmHealthy()
  try {
    writeAudit([rec({ tool: 'bash', decision: 'deny', reason: 'BLOCKED (network)' })])
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await runTurn(1)
    const afterFirst = turnFiles().length
    assert.equal(afterFirst, 1)

    await runTurn(2) // same records, nothing new
    assert.equal(turnFiles().length, afterFirst, 'no new records must not write a second report')
  } finally { __setExecOverride(null) }
})

test('U-03: rotation/trim below the old index does NOT silently skip a turn', async () => {
  tmHealthy()
  try {
    // 40 records, report the first 10 → watermark sits on record #9.
    const first = Array.from({ length: 40 }, () => rec({ tool: 'bash', decision: 'deny', reason: 'BLOCKED (network)' }))
    writeAudit(first)
    apply(mockCtx() as any, { protectedPaths: [ROOT] })

    // Boot-time handler must NOT fold pre-existing history in; seed the
    // watermark by reporting, then simulate the log being trimmed to 30.
    await runTurn(1)
    const filesAfter1 = turnFiles().length

    // Trim: drop the 10 oldest records (what rotation would do). Under the old
    // index logic (idx=40 vs length=33) this returned [] and skipped the turn.
    const trimmed = first.slice(10).concat(
      Array.from({ length: 3 }, () => rec({ tool: 'edit', decision: 'allow', reason: 'fresh write' })),
    )
    writeAudit(trimmed)
    assert.ok(trimmed.length < first.length + 3, 'sanity: window shrank')

    await runTurn(2)
    const filesAfter2 = turnFiles().length
    assert.ok(
      filesAfter2 > filesAfter1,
      `turn 2 must produce a report despite the shrink (before=${filesAfter1} after=${filesAfter2})`,
    )
  } finally { __setExecOverride(null) }
})

test('U-03: successive turns partition records — no overlap, no gap', async () => {
  tmHealthy()
  try {
    apply(mockCtx() as any, { protectedPaths: [ROOT] })

    // Denied records render their `reason` verbatim in the report, which makes
    // them a precise marker for "was this record included in this turn?".
    writeAudit([
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-a' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-b' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-c' }),
    ])
    const r1 = await runTurn(1)
    assert.match(r1, /turn1-a/)
    assert.match(r1, /turn1-c/)

    // Turn 2: two more, appended. Must contain ONLY the new two.
    writeAudit([
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-a' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-b' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn1-c' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn2-a' }),
      rec({ tool: 'bash', category: 'network', decision: 'deny', reason: 'BLOCKED turn2-b' }),
    ])

    const r2 = await runTurn(2)
    assert.match(r2, /turn2-a/, 'turn 2 must report its own records')
    assert.match(r2, /turn2-b/)
    assert.doesNotMatch(r2, /turn1-a/, 'turn 2 must NOT re-report turn 1 records')
    assert.doesNotMatch(r2, /turn1-c/)
  } finally { __setExecOverride(null) }
})

test('U-03: state.json round-trips and survives a plugin restart', async () => {
  tmHealthy()
  try {
    writeAudit([rec({ tool: 'bash', decision: 'deny', reason: 'BLOCKED (network)' })])
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await runTurn(1)
    const before = readState(join(ROOT, '.tm-guard')).reportWatermark
    assert.ok(before)

    // Restart: a fresh apply() must reload the watermark, so the same records
    // are not re-reported (the old code seeded from readAll().length, which
    // also suppressed this — the watermark must preserve that intent).
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    const filesBefore = turnFiles().length
    await runTurn(2)
    assert.equal(turnFiles().length, filesBefore, 'restart must not re-report old records')
    assert.deepEqual(readState(join(ROOT, '.tm-guard')).reportWatermark, before)
  } finally { __setExecOverride(null) }
})

test('U-03: corrupt state.json degrades to defaults instead of throwing', async () => {
  tmHealthy()
  try {
    writeAudit([rec({ tool: 'bash', decision: 'deny', reason: 'BLOCKED (network)' })])
    writeFileSync(statePath(), '{ this is not json', 'utf8')
    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await runTurn(1) // must not throw
    assert.ok(turnFiles().length >= 1, 'a report is still written')
    // Watermark is rewritten to a valid value.
    assert.ok(readState(join(ROOT, '.tm-guard')).reportWatermark)
  } finally { __setExecOverride(null) }
})

test('U-03: turnReports=false writes no report and no watermark', async () => {
  tmHealthy()
  try {
    writeAudit([rec({ tool: 'bash', decision: 'deny', reason: 'BLOCKED (network)' })])
    apply(mockCtx() as any, { protectedPaths: [ROOT], turnReports: false })
    await runTurn(1)
    assert.equal(turnFiles().length, 0)
  } finally { __setExecOverride(null) }
})

test('U-03: DEFAULT_CONFIG keeps turnReports on', () => {
  assert.equal(DEFAULT_CONFIG.turnReports, true)
})
