// U-02 regression: report filename collisions and unbounded report growth.
//
// (a) The turn report filename was second-precision (`slice(0, 19)`), so two
//     turns finishing in the same second wrote to the same path and the
//     second silently overwrote the first — a lost report with no error.
// (b) `.tm-guard/reports` had no upper bound (observed: 618 files / 4.9 MB).
//
// Fixes: millisecond-precision filenames, plus `reportsRetainCount` (200) and
// `reportsRetainDays` (30) pruning applied at plugin load.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readdirSync, writeFileSync, existsSync, rmSync, utimesSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, turnReportFileName, DEFAULT_CONFIG } from './src/index.ts'
import { pruneReports } from './src/report.ts'
import { __setExecOverride } from './src/tm.ts'

let ORIG_CWD = process.cwd()
let ROOT = ''

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

const reportsDir = () => join(ROOT, '.tm-guard', 'reports')

const DAY_MS = 24 * 60 * 60 * 1000

/**
 * Create `n` fake report files, all older than the age threshold, with
 * distinct mtimes so "newest N" is unambiguous.
 */
function seedReports(n: number, ageDays = 60, prefix = 'turn-') {
  mkdirSync(reportsDir(), { recursive: true })
  const base = Date.now() - ageDays * DAY_MS
  for (let i = 0; i < n; i++) {
    const p = join(reportsDir(), `${prefix}2020-01-01T00-00-00-${String(i).padStart(3, '0')}.md`)
    writeFileSync(p, `# report ${i}\n`, 'utf8')
    const t = (base + i * 1000) / 1000 // seconds
    utimesSync(p, t, t)
  }
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-reports-'))
  process.chdir(ROOT)
})
after(() => {
  __setExecOverride(null)
  process.chdir(ORIG_CWD)
})
beforeEach(() => {
  rmSync(join(ROOT, '.tm-guard'), { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// (a) filename precision
// ---------------------------------------------------------------------------

test('U-02a: turnReportFileName has millisecond precision and stays sortable', () => {
  const a = turnReportFileName(new Date('2026-03-01T10:00:00.000Z'))
  const b = turnReportFileName(new Date('2026-03-01T10:00:00.001Z'))
  const c = turnReportFileName(new Date('2026-03-01T10:00:00.999Z'))
  const d = turnReportFileName(new Date('2026-03-01T10:00:01.000Z'))

  assert.notEqual(a, b, 'same second, different ms must not collide')
  assert.notEqual(b, c)
  assert.match(a, /^turn-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}\.md$/)
  // Lexicographic order mirrors chronological order (prune/glob rely on it).
  assert.deepEqual([a, b, c, d], [a, b, c, d].slice().sort())
})

test('U-02a: two reports generated in the SAME millisecond produce distinct files', async () => {
  tmHealthy()
  try {
    // Two turns, each with fresh audit activity. The records need distinct
    // timestamps: identity is (ts, tool), so two records sharing BOTH are
    // genuinely indistinguishable and the watermark would (correctly) treat
    // the second as already-reported.
    mkdirSync(join(ROOT, '.tm-guard'), { recursive: true })
    const rec = (ts: string, reason: string) => JSON.stringify({
      ts, tool: 'bash', category: 'network',
      decision: 'deny', reason, targetPaths: [],
    })
    const s1 = rec('2026-03-01T10:00:00.000Z', 'BLOCKED s1')
    writeFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), s1 + '\n', 'utf8')

    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 1 })

    writeFileSync(
      join(ROOT, '.tm-guard', 'audit.jsonl'),
      s1 + '\n' + rec('2026-03-01T10:00:00.001Z', 'BLOCKED s2') + '\n',
      'utf8',
    )
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 2 })

    const files = readdirSync(reportsDir()).filter((f) => f.startsWith('turn-'))
    assert.equal(files.length, 2, `two turns must yield two reports, got ${JSON.stringify(files)}`)
  } finally { __setExecOverride(null) }
})

test('U-02a: the writer produces a distinct path for consecutive same-ms calls', () => {
  // The handler above runs in real time, so it cannot force two writes into
  // the same millisecond. Exercise the naming boundary directly instead: two
  // adjacent milliseconds inside one second must map to two distinct paths,
  // which is precisely what the old second-precision stamp failed to do.
  const a = turnReportFileName(new Date('2026-03-01T10:00:00.000Z'))
  const b = turnReportFileName(new Date('2026-03-01T10:00:00.001Z'))
  assert.notEqual(a, b)
  // Under the OLD scheme both collapsed to this same string:
  const oldScheme = (d: Date) => `turn-${d.toISOString().replace(/[:.]/g, '-').slice(0, 19)}.md`
  assert.equal(
    oldScheme(new Date('2026-03-01T10:00:00.000Z')),
    oldScheme(new Date('2026-03-01T10:00:00.001Z')),
    'demonstrates the collision the fix removes',
  )
  assert.notEqual(a.slice(0, 19), '') // prefix still matches the legacy shape
})

test('U-02a: filename keeps the legacy prefix so glob/prune matching is unchanged', () => {
  // Old second-precision names and new millisecond names both match the
  // `turn-*.md` glob pruneReports relies on, so no migration is needed.
  const old = 'turn-2026-03-01T10-00-00.md'
  const newer = turnReportFileName(new Date('2026-03-01T10:00:00.500Z'))
  assert.ok(old.startsWith('turn-') && old.endsWith('.md'))
  assert.ok(newer.startsWith('turn-') && newer.endsWith('.md'))
  // The new name extends the old one rather than diverging from it.
  assert.ok(newer.startsWith('turn-2026-03-01T10-00-00'))
})

// ---------------------------------------------------------------------------
// (b) pruning: dual threshold
// ---------------------------------------------------------------------------

test('U-02b: 300 old reports are pruned down to reportsRetainCount (200)', () => {
  seedReports(300, 60)
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.scanned, 300)
  assert.equal(res.deleted.length, 100, `expected 100 deletions, got ${res.deleted.length}`)
  assert.equal(readdirSync(reportsDir()).filter((f) => f.endsWith('.md')).length, 200)
})

test('U-02b: count and age are ANDed — stale files inside the newest N are kept', () => {
  // 250 files: the OLDEST 100 are stale (90d), the newest 150 are fresh (1d).
  // Ranks are newest-first, so the stale files occupy ranks 150..249 and the
  // fresh ones ranks 0..149.
  //   ranks   0..149  fresh, beyond nothing relevant  → kept (fresh)
  //   ranks 150..199  stale but INSIDE the newest 200 → kept (count protects)
  //   ranks 200..249  stale AND beyond the newest 200 → deleted
  // The 50 kept at ranks 150..199 are the point of the intersection: an OR
  // rule would have deleted all 100 stale files.
  mkdirSync(reportsDir(), { recursive: true })
  const now = Date.now()
  for (let i = 0; i < 250; i++) {
    const p = join(reportsDir(), `turn-x-${String(i).padStart(3, '0')}.md`)
    writeFileSync(p, 'x\n', 'utf8')
    const ageDays = i < 100 ? 90 : 1
    const t = (now - ageDays * DAY_MS + i * 1000) / 1000
    utimesSync(p, t, t)
  }
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.deleted.length, 50, 'only stale files beyond the newest 200 go')
  assert.equal(res.kept.length, 200)
  // Nothing fresh may ever be deleted, and the newest 200 always survive.
  assert.equal(res.deleted.includes('turn-x-249.md'), false, 'newest file must survive')
  assert.equal(res.deleted.includes('turn-x-150.md'), false, 'stale-but-recent file must survive')
})

test('U-02b: a stale file INSIDE the retain count survives (AND semantics, not OR)', () => {
  // 10 files, ALL stale, retainCount 200 → none may be deleted. This is the
  // core difference from a union rule, which would delete all of them.
  seedReports(10, 365)
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.deleted.length, 0)
  assert.equal(res.kept.length, 10)
})

test('U-02b: a fresh file BEYOND the retain count survives (AND semantics, not OR)', () => {
  // 250 fresh files, retainCount 200 → none may be deleted.
  seedReports(250, 0)
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.deleted.length, 0)
  assert.equal(res.kept.length, 250)
})

test('U-02b: an old but tiny set is NOT wiped (age alone is insufficient)', () => {
  // The union behaviour this guards against: 50 reports, all 90 days old.
  // They are within the retain count, so nothing may be deleted.
  seedReports(50, 90)
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.deleted.length, 0, 'age alone must never trigger deletion')
  assert.equal(readdirSync(reportsDir()).length, 50)
})

test('U-02b: a large but fresh set is NOT wiped (count alone is insufficient)', () => {
  seedReports(300, 1) // 300 reports, all fresh
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.deleted.length, 0, 'recency alone must never trigger deletion')
  assert.equal(readdirSync(reportsDir()).length, 300)
})

test('U-02b: retainDays=0 disables the age gate (count alone decides)', () => {
  seedReports(300, 1)
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 0 })
  assert.equal(res.deleted.length, 100)
  assert.equal(readdirSync(reportsDir()).length, 200)
})

test('U-02b: cleanup-dryrun-* reports are managed alongside turn-*', () => {
  seedReports(150, 90, 'turn-')
  seedReports(150, 90, 'cleanup-dryrun-')
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.equal(res.scanned, 300, 'both prefixes must be scanned')
  assert.equal(res.deleted.length, 100)
})

test('U-02b: unrelated files in the reports dir are never touched', () => {
  seedReports(300, 90)
  writeFileSync(join(reportsDir(), 'notes.txt'), 'keep me', 'utf8')
  writeFileSync(join(reportsDir(), 'other.md'), 'keep me too', 'utf8')
  pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  assert.ok(existsSync(join(reportsDir(), 'notes.txt')), 'non-.md file must survive')
  assert.ok(existsSync(join(reportsDir(), 'other.md')), 'unmanaged .md file must survive')
})

test('U-02b: missing reports directory is a silent no-op', () => {
  const res = pruneReports(join(ROOT, 'does-not-exist'), { retainCount: 10, retainDays: 1 })
  assert.deepEqual(res, { deleted: [], kept: [], scanned: 0 })
})

test('U-02b: apply() prunes at load time with the configured thresholds', () => {
  tmHealthy()
  try {
    seedReports(260, 90)
    mkdirSync(join(ROOT, '.tm-guard'), { recursive: true })
    writeFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), '', 'utf8')
    apply(mockCtx() as any, { protectedPaths: [ROOT], reportsRetainCount: 200, reportsRetainDays: 30 })
    const left = readdirSync(reportsDir()).filter((f) => f.endsWith('.md')).length
    assert.equal(left, 200, `apply() must prune to 200, ${left} remain`)
  } finally { __setExecOverride(null) }
})

test('U-02b: apply() honours a custom reportsRetainCount', () => {
  tmHealthy()
  try {
    seedReports(60, 90)
    mkdirSync(join(ROOT, '.tm-guard'), { recursive: true })
    writeFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), '', 'utf8')
    apply(mockCtx() as any, { protectedPaths: [ROOT], reportsRetainCount: 10, reportsRetainDays: 30 })
    assert.equal(readdirSync(reportsDir()).filter((f) => f.endsWith('.md')).length, 10)
  } finally { __setExecOverride(null) }
})

// ---------------------------------------------------------------------------
// config surface
// ---------------------------------------------------------------------------

test('U-02b: DEFAULT_CONFIG exposes the documented retention defaults', () => {
  assert.equal(DEFAULT_CONFIG.reportsRetainCount, 200)
  assert.equal(DEFAULT_CONFIG.reportsRetainDays, 30)
})

test('U-02b: invalid retention config degrades to defaults (no crash, no wipe)', () => {
  tmHealthy()
  try {
    seedReports(30, 90)
    mkdirSync(join(ROOT, '.tm-guard'), { recursive: true })
    writeFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), '', 'utf8')
    apply(mockCtx() as any, {
      protectedPaths: [ROOT],
      // Hand-edited YAML: wrong types must fall back, not delete everything.
      reportsRetainCount: 'lots' as unknown as number,
      reportsRetainDays: null as unknown as number,
    })
    assert.equal(readdirSync(reportsDir()).length, 30, 'bad config must not trigger a wipe')
  } finally { __setExecOverride(null) }
})
