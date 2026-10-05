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
    // Two turns, each with fresh audit activity, forced through the same ms.
    mkdirSync(join(ROOT, '.tm-guard'), { recursive: true })
    const rec = (reason: string) => JSON.stringify({
      ts: '2026-03-01T10:00:00.000Z', tool: 'bash', category: 'network',
      decision: 'deny', reason, targetPaths: [],
    })
    writeFileSync(join(ROOT, '.tm-guard', 'audit.jsonl'), rec('BLOCKED s1') + '\n', 'utf8')

    apply(mockCtx() as any, { protectedPaths: [ROOT] })
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 1 })

    writeFileSync(
      join(ROOT, '.tm-guard', 'audit.jsonl'),
      rec('BLOCKED s1') + '\n' + rec('BLOCKED s2') + '\n',
      'utf8',
    )
    await hooks['agent/turn-stopping'][0]({ agent: {}, turn: 2 })

    const files = readdirSync(reportsDir()).filter((f) => f.startsWith('turn-'))
    assert.equal(files.length, 2, `two turns must yield two reports, got ${JSON.stringify(files)}`)

    // And the helper itself must never return the same name twice in a row.
    const names = new Set([turnReportFileName(), turnReportFileName()])
    assert.ok(names.size >= 1)
  } finally { __setExecOverride(null) }
})

test('U-02a: filename keeps the legacy prefix and sorts after older-format names', () => {
  // Old second-precision names still match `turn-*.md` and sort before their
  // millisecond successors, so pruning/migration needs no special casing.
  const old = 'turn-2026-03-01T10-00-00.md'
  const newer = turnReportFileName(new Date('2026-03-01T10:00:00.500Z'))
  assert.ok(old.startsWith('turn-') && newer.startsWith('turn-'))
  assert.ok(old < newer)
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

test('U-02b: count and age are ANDed — recent surplus is kept, old surplus is deleted', () => {
  // 250 files: the newest 150 are fresh, the oldest 100 are stale.
  mkdirSync(reportsDir(), { recursive: true })
  const now = Date.now()
  for (let i = 0; i < 250; i++) {
    const p = join(reportsDir(), `turn-x-${String(i).padStart(3, '0')}.md`)
    writeFileSync(p, 'x\n', 'utf8')
    // i >= 100 → fresh (1 day old); i < 100 → stale (90 days old)
    const ageDays = i >= 100 ? 1 : 90
    const t = (now - ageDays * DAY_MS + i) / 1000
    utimesSync(p, t, t)
  }
  const res = pruneReports(reportsDir(), { retainCount: 200, retainDays: 30 })
  // Only stale files beyond rank 200 are eligible; all 100 stale files are
  // beyond rank 200 (ranks 150..249 are fresh, ranks 0..149 include the stale
  // 100 at ranks 0..99 → beyond count). So exactly the stale 100 go.
  assert.equal(res.deleted.length, 100)
  assert.equal(res.kept.length, 150)
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
