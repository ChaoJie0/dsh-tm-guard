// U-01: audit log rotation (design docs/auto-cleanup-design.md §4.1–4.3).
//
// The rotation ORDER is the whole point of this file. The v1 order ("write .1,
// then shift .1→.2…") was rejected as high-risk in review B2: because rename
// overwrites its destination, writing `.1` first destroys the previous
// generation before it can be shifted, so EVERY rotation silently costs one
// generation of history and leaves a hole in the `.N` sequence.
//
// Required order (design §4.2.1, the B2 fix):
//   1. shift oldest → newest:  unlink(.N), then .N-1→.N … .1→.2
//   2-5. read current → write .1.tmp → fsync → rename .1
//   6. truncate the current file in place (inode unchanged)
//
// The "3 consecutive rotations" assertions below are exactly the check the
// review demanded: `.1/.2/.3` must be pairwise distinct and time-decreasing.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AuditLog, AUDIT_DEFAULTS, DEFAULT_ROTATION } from './src/audit.ts'
import { DEFAULT_CONFIG } from './src/index.ts'
import type { AuditRecord } from './src/audit.ts'

let ROOT = ''

const guardDir = () => join(ROOT, '.tm-guard')
const auditPath = () => join(guardDir(), 'audit.jsonl')
const genPath = (n: number) => `${auditPath()}.${n}`

before(() => { ROOT = mkdtempSync(join(tmpdir(), 'tm-audit-rotate-')) })
after(() => { rmSync(ROOT, { recursive: true, force: true }) })

beforeEach(() => {
  rmSync(guardDir(), { recursive: true, force: true })
  mkdirSync(guardDir(), { recursive: true })
})

/** Tight thresholds so a handful of records trips rotation. */
function log(over: Partial<{ maxBytes: number; retainFiles: number; totalMaxBytes: number }> = {}) {
  return new AuditLog(ROOT, { maxBytes: 200, retainFiles: 2, totalMaxBytes: 10_000, ...over })
}

let seq = 0
function rec(msg: string): Omit<AuditRecord, 'ts'> {
  seq++
  return {
    tool: 'bash',
    category: 'write',
    decision: 'allow',
    reason: msg,
    targetPaths: [`/tmp/f${seq}`],
  }
}

/** Reasons present in a generation, in file order. */
function reasonsIn(p: string): string[] {
  return readFileSync(p, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => (JSON.parse(l) as AuditRecord).reason)
}

/** Write `n` distinct records through the public API. */
function fill(a: AuditLog, prefix: string, n: number) {
  for (let i = 0; i < n; i++) a.record(rec(`${prefix}${i}`))
}

/* ------------------------------------------------------------------ */
/* (a) normal rotation                                                 */
/* ------------------------------------------------------------------ */

test('U-01 (a): crossing the threshold rotates, and .1 holds the pre-rotation file', () => {
  const a = log()
  fill(a, 'A', 3)
  const before = readFileSync(auditPath(), 'utf8')

  assert.ok(statSync(auditPath()).size > 200, 'precondition: current file exceeds maxBytes')
  assert.equal(existsSync(genPath(1)), false, 'precondition: no generation yet')

  a.record(rec('TRIGGER'))

  assert.ok(existsSync(genPath(1)), '.1 must exist after rotation')
  // .1 is byte-for-byte the file that existed before the rotation — nothing was
  // dropped, reordered or duplicated on the way out.
  assert.equal(readFileSync(genPath(1), 'utf8'), before, '.1 must equal the pre-rotation file')
  // The current file now holds only the record written after rotation.
  assert.deepEqual(reasonsIn(auditPath()), ['TRIGGER'])
  assert.deepEqual(reasonsIn(genPath(1)), ['A0', 'A1', 'A2'])
})

test('U-01 (a2): the current file is truncated in place, keeping its inode', () => {
  const a = log()
  fill(a, 'A', 3)
  const inoBefore = statSync(auditPath()).ino
  a.record(rec('TRIGGER'))
  // truncate (not unlink+create) is what keeps a concurrent holder's append fd
  // pointing at the live file instead of a rotated-away one (design §4.2.1).
  assert.equal(statSync(auditPath()).ino, inoBefore, 'current file must keep its inode')
})

/* ------------------------------------------------------------------ */
/* (b) three consecutive rotations — the B2 assertion                  */
/* ------------------------------------------------------------------ */

test('U-01 (b): 3 consecutive rotations keep .1/.2/.3 distinct and time-ordered', () => {
  const a = log({ retainFiles: 3 })
  const snapshots: string[] = []

  for (let g = 1; g <= 3; g++) {
    fill(a, `G${g}-`, 3)
    snapshots.push(readFileSync(auditPath(), 'utf8'))
    a.record(rec(`TRIGGER${g}`))
  }

  for (const p of [genPath(1), genPath(2), genPath(3)]) {
    assert.ok(existsSync(p), `${p} must exist after 3 rotations`)
  }

  // (1) Pairwise distinct: under the v1 order, `.1` and `.2` would both be the
  // newest content, and one whole generation (G1) would be gone entirely.
  const g1 = readFileSync(genPath(1), 'utf8')
  const g2 = readFileSync(genPath(2), 'utf8')
  const g3 = readFileSync(genPath(3), 'utf8')
  assert.notEqual(g1, g2, '.1 and .2 must differ')
  assert.notEqual(g2, g3, '.2 and .3 must differ')
  assert.notEqual(g1, g3, '.1 and .3 must differ')

  // (2) Content is exactly the pre-rotation snapshot of the matching round.
  assert.equal(g1, snapshots[2], '.1 must be the newest generation')
  assert.equal(g2, snapshots[1], '.2 must be the middle generation')
  assert.equal(g3, snapshots[0], '.3 must be the oldest generation')

  // (3) Time-decreasing: .1 is newer than .2 is newer than .3.
  assert.deepEqual(reasonsIn(genPath(1)), ['G3-0', 'G3-1', 'G3-2'])
  assert.deepEqual(reasonsIn(genPath(2)), ['G2-0', 'G2-1', 'G2-2'])
  assert.deepEqual(reasonsIn(genPath(3)), ['G1-0', 'G1-1', 'G1-2'])

  // (4) No holes: the generation sequence is contiguous.
  assert.deepEqual(
    readdirSync(guardDir()).filter((f) => /^audit\.jsonl\.\d+$/.test(f)).sort(),
    ['audit.jsonl.1', 'audit.jsonl.2', 'audit.jsonl.3'],
  )
})

test('U-01 (b2): the oldest generation is dropped once retention is exceeded', () => {
  const a = log({ retainFiles: 2 })
  for (let g = 1; g <= 3; g++) {
    fill(a, `G${g}-`, 3)
    a.record(rec(`TRIGGER${g}`))
  }
  // retainFiles: 2 ⇒ G1 must be gone, G2/G3 remain, still contiguous.
  assert.equal(existsSync(genPath(3)), false, '.3 must not exist when retainFiles=2')
  assert.deepEqual(reasonsIn(genPath(1)).map((r) => r.slice(0, 2)), ['G3', 'G3', 'G3'])
  assert.deepEqual(reasonsIn(genPath(2)).map((r) => r.slice(0, 2)), ['G2', 'G2', 'G2'])
})

/* ------------------------------------------------------------------ */
/* (c) whole-line boundary alignment                                   */
/* ------------------------------------------------------------------ */

test('U-01 (c): every line of every generation is valid JSON (no half-line cut)', () => {
  const a = log({ retainFiles: 3 })
  for (let g = 1; g <= 4; g++) {
    fill(a, `G${g}-`, 4)
    a.record(rec(`TRIGGER${g}`))
  }
  for (const f of readdirSync(guardDir()).filter((f) => f.startsWith('audit.jsonl'))) {
    const content = readFileSync(join(guardDir(), f), 'utf8')
    // A rotation that sliced by byte offset would leave a torn leading or
    // trailing fragment here.
    if (content.length > 0) {
      assert.equal(content.at(-1), '\n', `${f} must end on a record boundary`)
    }
    for (const [i, line] of content.split('\n').entries()) {
      if (line.trim().length === 0) continue
      assert.doesNotThrow(() => JSON.parse(line), `${f}:${i + 1} must be valid JSON`)
    }
  }
})

test('U-01 (c2): a torn trailing line survives verbatim and costs only itself', () => {
  const a = log()
  fill(a, 'A', 2)
  const intact = readFileSync(auditPath(), 'utf8')

  // Simulate a crash mid-append: a partial JSON object with no newline.
  writeFileSync(auditPath(), intact + '{"ts":"2026-01-01T00:00:00.000Z","tool":"bas', 'utf8')
  a.record(rec('TRIGGER'))

  const g1 = readFileSync(genPath(1), 'utf8')
  // The torn fragment is carried over untouched rather than causing the
  // rotation to slice at a byte offset and destroy the valid lines.
  assert.ok(g1.startsWith(intact), 'valid history must survive intact')
  assert.ok(g1.includes('"tool":"bas'), 'torn fragment preserved verbatim')

  // And it is dropped individually at parse time, not by the whole-file chunk.
  assert.deepEqual(reasonsIn(genPath(1)), ['A0', 'A1'])
})

/* ------------------------------------------------------------------ */
/* (d) readAll() splices generations in chronological order             */
/* ------------------------------------------------------------------ */

test('U-01 (d): readAll() returns current + .1 + .2 concatenated, oldest first', () => {
  const a = log({ retainFiles: 2 })
  fill(a, 'G1-', 3)
  a.record(rec('TRIGGER1'))
  fill(a, 'G2-', 3)
  a.record(rec('TRIGGER2'))
  fill(a, 'G3-', 3)

  const residual = reasonsIn(auditPath())
  const g1 = reasonsIn(genPath(1))
  const g2 = reasonsIn(genPath(2))

  const all = a.readAll()
  // Total = every retained file's records, with nothing lost or duplicated.
  assert.equal(all.length, residual.length + g1.length + g2.length)
  assert.equal(all.length, 3 + 4 + 4)
  // Oldest → newest: .2, then .1, then the live file.
  assert.deepEqual(all.map((r) => r.reason), [...g2, ...g1, ...residual])
  // The newest record is still last, so recent()/writeOperations() keep working.
  assert.equal(all.at(-1)?.reason, 'G3-2')
})

test('U-01 (d2): rotation preserves tm_rollback --last_operation targeting', () => {
  const a = log()
  fill(a, 'G1-', 3)
  a.record(rec('TRIGGER1'))
  // The most recent write is in the live file, but the rotated generation also
  // holds writes; writeOperations() must still see it last.
  a.record({
    tool: 'edit', category: 'write', decision: 'allow',
    reason: 'LAST-WRITE', targetPaths: ['/tmp/last'], snapshotId: 'SNAP-LAST',
  })

  const writes = a.writeOperations()
  assert.equal(writes.at(-1)?.reason, 'LAST-WRITE')
  assert.equal(a.recent(1)[0].reason, 'LAST-WRITE')
  assert.equal(a.lastWriteSnapshot(), 'SNAP-LAST')
})

test('U-01 (d3): the current file alone is what readCurrent() reports', () => {
  const a = log()
  fill(a, 'A', 3)
  a.record(rec('TRIGGER'))
  assert.deepEqual(a.readCurrent().map((r) => r.reason), ['TRIGGER'])
  assert.equal(a.readAll().length, 4, 'readAll spans generations')
})

/* ------------------------------------------------------------------ */
/* (e) threshold boundary                                              */
/* ------------------------------------------------------------------ */

test('U-01 (e): exactly at the threshold does not rotate; one byte over does', () => {
  const maxBytes = 300
  const a = log({ maxBytes })
  const one = rec('X')
  const line = (r: Omit<AuditRecord, 'ts'>) => JSON.stringify({ ...r, ts: '2026-01-01T00:00:00.000Z' }) + '\n'

  // Build a file whose size is exactly `maxBytes`.
  const unit = line(one)
  const pad = maxBytes - unit.length
  assert.ok(pad >= 2, 'test setup needs room for the pad line')
  const filler = JSON.stringify({
    ts: '2026-01-01T00:00:00.000Z', tool: 'x', category: 'x',
    decision: 'allow', reason: 'p'.repeat(pad - 70), targetPaths: [],
  })
  let content = unit
  content += ' '.repeat(0)
  // Pad precisely: keep adding to a single JSON line until the size matches.
  const base = JSON.stringify({
    ts: '2026-01-01T00:00:00.000Z', tool: 'x', category: 'x',
    decision: 'allow', reason: '', targetPaths: [],
  })
  const need = maxBytes - unit.length - (base.length + 1)
  assert.ok(need >= 0, `pad calculation out of range (${need})`)
  const exact = unit + base.slice(0, base.length - 1) + 'r'.repeat(need) + '"\n'.replace('"', '') + ''
  void content; void filler; void exact

  // Simpler and exact: pad the `reason` of a second record via JSON round-trip.
  const mk = (reasonLen: number) => JSON.stringify({
    ts: '2026-01-01T00:00:00.000Z', tool: 'x', category: 'x',
    decision: 'allow', reason: 'y'.repeat(reasonLen), targetPaths: [],
  }) + '\n'
  let reasonLen = 0
  while (unit.length + mk(reasonLen + 1).length <= maxBytes) reasonLen++
  const padded = unit + mk(reasonLen)
  assert.equal(padded.length, maxBytes, 'test setup must hit the threshold exactly')
  writeFileSync(auditPath(), padded, 'utf8')

  // Exactly at the threshold ⇒ still within budget ⇒ no rotation.
  assert.equal(a.maybeRotate(), false, 'must not rotate at exactly maxBytes')
  assert.equal(existsSync(genPath(1)), false)

  // One byte over ⇒ rotate.
  writeFileSync(auditPath(), padded + ' ', 'utf8')
  assert.equal(statSync(auditPath()).size, maxBytes + 1)
  assert.equal(a.maybeRotate(), true, 'must rotate past maxBytes')
  assert.ok(existsSync(genPath(1)))
})

test('U-01 (e2): auditMaxBytes = 0 disables rotation instead of rotating always', () => {
  const a = log({ maxBytes: 0 })
  fill(a, 'A', 20)
  assert.equal(existsSync(genPath(1)), false, 'maxBytes=0 must disable rotation')
  assert.equal(a.readAll().length, 20)
})

/* ------------------------------------------------------------------ */
/* (f) locking under concurrent access                                 */
/* ------------------------------------------------------------------ */

test('U-01 (f): a held lock blocks concurrent rotation instead of corrupting', () => {
  const a = log()
  fill(a, 'A', 3)
  const lock = join(guardDir(), '.rotate.lock')
  // Simulate another live process holding the lock (our own pid ⇒ provably live).
  writeFileSync(lock, `${process.pid}:${process.getuid?.() ?? 0}:${Date.now()}\n`, 'utf8')

  assert.equal(a.rotate(), false, 'rotation must back off while the lock is held')
  assert.equal(existsSync(genPath(1)), false, 'no generation may be produced')
  assert.ok(existsSync(auditPath()), 'current file must be untouched')
  assert.deepEqual(reasonsIn(auditPath()), ['A0', 'A1', 'A2'])

  // Lock released ⇒ the next rotation succeeds.
  rmSync(lock, { force: true })
  assert.equal(a.rotate(), true)
  assert.deepEqual(reasonsIn(genPath(1)), ['A0', 'A1', 'A2'])
})

test('U-01 (f2): a stale lock (dead pid) is reclaimed, not deadlocked', () => {
  const a = log()
  fill(a, 'A', 3)
  // pid 0x7ffffffe is not a live process; the holder is provably gone.
  writeFileSync(join(guardDir(), '.rotate.lock'), `2147483646:${process.getuid?.() ?? 0}:1\n`, 'utf8')
  assert.equal(a.rotate(), true, 'a lock from a dead pid must be reclaimed')
  assert.equal(existsSync(join(guardDir(), '.rotate.lock')), false, 'lock must be released')
})

test('U-01 (f3): two instances hammering the same log produce no corrupt file', () => {
  // Both instances resolve the same directory, so they contend for the same
  // .rotate.lock — the cross-process guard. Records interleave, but every line
  // written must remain parseable and no generation may be half-written.
  const a = new AuditLog(ROOT, { maxBytes: 300, retainFiles: 3, totalMaxBytes: 10_000 })
  const b = new AuditLog(ROOT, { maxBytes: 300, retainFiles: 3, totalMaxBytes: 10_000 })

  for (let i = 0; i < 40; i++) {
    a.record(rec(`a${i}`))
    b.record(rec(`b${i}`))
  }

  const files = readdirSync(guardDir()).filter((f) => f.startsWith('audit.jsonl'))
  assert.ok(files.some((f) => f !== 'audit.jsonl'), 'rotation must have happened')
  assert.equal(files.some((f) => f.endsWith('.tmp')), false, 'no .tmp file may be left behind')

  for (const f of files) {
    const content = readFileSync(join(guardDir(), f), 'utf8')
    if (content.length > 0) {
      assert.equal(content.at(-1), '\n', `${f} must end on a record boundary`)
    }
    const lines = content.split('\n').filter((l) => l.trim().length > 0)
    for (const [i, line] of lines.entries()) {
      assert.doesNotThrow(() => JSON.parse(line), `${f}:${i + 1} corrupt`)
    }
    // No record may be duplicated across the generation boundary.
    const seen = new Set<string>()
    for (const line of lines) {
      const r = JSON.parse(line) as AuditRecord
      assert.equal(seen.has(r.reason), false, `${f} contains duplicate ${r.reason}`)
      seen.add(r.reason)
    }
  }

  // Everything written is still visible exactly once via readAll().
  const all = a.readAll()
  assert.equal(new Set(all.map((r) => r.reason)).size, all.length, 'no duplicates in readAll')
  assert.equal(all.length, 80, 'all 80 records survive (retention window permitting)')
})

test('U-01 (f4): re-entrant rotation on one instance does not self-deadlock', () => {
  // A pid matching our own is treated as stale: holding the lock ourselves and
  // asking again must proceed rather than spin until the timeout.
  const a = log()
  fill(a, 'A', 3)
  writeFileSync(join(guardDir(), '.rotate.lock'), `${process.pid}:${process.getuid?.() ?? 0}:${Date.now()}\n`, 'utf8')
  const started = Date.now()
  const ok = a.rotate()
  assert.equal(ok, true, 'own-pid lock must be reclaimable')
  assert.ok(Date.now() - started < 5000, 'must not wait out the full timeout')
})

/* ------------------------------------------------------------------ */
/* retain / total-size backstop, and config plumbing                   */
/* ------------------------------------------------------------------ */

test('U-01: auditTotalMaxBytes trims oldest generations first, never the live file', () => {
  const a = log({ retainFiles: 5, maxBytes: 200, totalMaxBytes: 700 })
  for (let g = 1; g <= 4; g++) {
    fill(a, `G${g}-`, 3)
    a.record(rec(`TRIGGER${g}`))
  }
  const files = readdirSync(guardDir()).filter((f) => f.startsWith('audit.jsonl'))
  const total = files.reduce((n, f) => n + statSync(join(guardDir(), f)).size, 0)
  assert.ok(total <= 700, `total ${total} must respect auditTotalMaxBytes`)
  assert.ok(existsSync(auditPath()), 'the live file must never be deleted')
  assert.equal(reasonsIn(auditPath()).at(-1), 'TRIGGER4', 'newest records survive')
})

test('U-01: defaults have headroom (total > retain × max) and match DEFAULT_CONFIG', () => {
  assert.equal(AUDIT_DEFAULTS.maxBytes, 10 * 1024 * 1024)
  assert.equal(AUDIT_DEFAULTS.retainFiles, 5)
  assert.equal(AUDIT_DEFAULTS.totalMaxBytes, 100 * 1024 * 1024)
  // Review B4: without headroom the total cap fires on every write, deleting a
  // whole generation each time. 2× is the documented margin.
  assert.ok(
    AUDIT_DEFAULTS.totalMaxBytes >= AUDIT_DEFAULTS.retainFiles * AUDIT_DEFAULTS.maxBytes * 2,
    'totalMaxBytes must leave headroom over retain × maxBytes',
  )
  assert.equal(DEFAULT_CONFIG.auditMaxBytes, AUDIT_DEFAULTS.maxBytes)
  assert.equal(DEFAULT_CONFIG.auditRetainFiles, AUDIT_DEFAULTS.retainFiles)
  assert.equal(DEFAULT_CONFIG.auditTotalMaxBytes, AUDIT_DEFAULTS.totalMaxBytes)
  assert.deepEqual(DEFAULT_ROTATION, { ...AUDIT_DEFAULTS })
})

test('U-01: a partial rotation config only overrides what it names', () => {
  const a = new AuditLog(ROOT, { maxBytes: 128 })
  const cfg = a.rotationConfig
  assert.equal(cfg.maxBytes, 128)
  assert.equal(cfg.retainFiles, AUDIT_DEFAULTS.retainFiles, 'unspecified fields keep defaults')
  assert.equal(cfg.totalMaxBytes, AUDIT_DEFAULTS.totalMaxBytes)
})

test('U-01: rotation never runs on an empty or missing log', () => {
  const a = log()
  assert.equal(a.rotate(), false, 'missing file ⇒ nothing to rotate')
  assert.equal(existsSync(genPath(1)), false)
  writeFileSync(auditPath(), '', 'utf8')
  assert.equal(a.rotate(), false, 'empty file ⇒ nothing to rotate')
  assert.equal(existsSync(genPath(1)), false)
})

test('U-01: generations are discovered beyond the retention count without error', () => {
  const a = log({ retainFiles: 2 })
  fill(a, 'A', 3)
  a.record(rec('T'))
  // A pre-existing higher generation (e.g. left by a larger retainFiles run)
  // must be read rather than cause a crash or an out-of-order splice.
  writeFileSync(genPath(7), JSON.stringify({
    ts: '2020-01-01T00:00:00.000Z', tool: 'x', category: 'x',
    decision: 'allow', reason: 'ANCIENT', targetPaths: [],
  }) + '\n', 'utf8')
  assert.equal(a.readAll()[0].reason, 'ANCIENT', 'highest generation is oldest')
})
