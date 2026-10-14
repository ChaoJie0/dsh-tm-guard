// Fault-injection tests for audit.ts — the gate's evidence chain.
//
// audit.ts is pure fs work (no subprocesses), so failures are injected with
// real filesystem state: a read-only workspace forces the /tmp fallback, a
// deleted log dir forces append/read/clear failures, a corrupt line is
// skipped by readAll. Success-path roundtrips are included for contrast.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { AuditLog } from './src/audit.ts'
import {
  appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync,
} from 'node:fs'
import { join } from 'node:path'

const dirs: string[] = []
function tmpDir(tag: string): string {
  const d = mkdtempSync(`/tmp/audit-faults-${tag}-`)
  dirs.push(d)
  return d
}

after(() => {
  for (const d of dirs) {
    try { chmodSync(d, 0o755) } catch { /* best effort */ }
    try { rmSync(d, { recursive: true, force: true }) } catch { /* best effort */ }
  }
})

// ---------------------------------------------------------------------------
test('roundtrip: record -> readAll -> recent -> writeOperations -> clear', () => {
  const d = tmpDir('basic')
  const a = new AuditLog(d)
  assert.equal(a.dirPath, join(d, '.tm-guard'))
  a.record({ tool: 'bash', category: 'read', decision: 'allow', reason: 'ok', targetPaths: [] })
  a.record({ tool: 'bash', category: 'file_write', decision: 'allow', reason: 'w', targetPaths: ['/x'], snapshotId: 'snap-1' })
  a.record({ tool: 'bash', category: 'read', decision: 'deny', reason: 'blocked', targetPaths: [] })
  const all = a.readAll()
  assert.equal(all.length, 3)
  assert.equal(all[0].ts !== undefined, true)
  assert.equal(all[1].snapshotId, 'snap-1')
  assert.equal(a.recent(2).length, 2)
  const writes = a.writeOperations()
  assert.equal(writes.length, 1)
  assert.equal(writes[0].targetPaths[0], '/x')
  assert.equal(a.lastWriteSnapshot(), 'snap-1')
  a.clear()
  assert.equal(a.readAll().length, 0)
})

test('lastWriteSnapshot: undefined when writes carry no snapshot', () => {
  const a = new AuditLog(tmpDir('nosnap'))
  a.record({ tool: 'w', category: 'file_write', decision: 'allow', reason: 'r', targetPaths: ['/y'] })
  a.record({ tool: 'r', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  assert.equal(a.lastWriteSnapshot(), undefined)
})

test('readAll: corrupt lines are skipped, missing file -> []', () => {
  const d = tmpDir('corrupt')
  const a = new AuditLog(d)
  a.record({ tool: 'x', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  // append garbage manually
  appendFileSync(a.path, 'not-json{{{')
  appendFileSync(a.path, '\n')
  a.record({ tool: 'y', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  const all = a.readAll()
  assert.equal(all.length, 2) // two valid, one garbage skipped
  // missing log file -> []
  rmSync(a.path)
  assert.deepEqual(a.readAll(), [])
})

// ---------------------------------------------------------------------------
test('constructor: read-only workspace falls back to /tmp/.tm-guard', () => {
  const ro = tmpDir('ro')
  chmodSync(ro, 0o555) // read-only parent -> mkdir .tm-guard fails
  const a = new AuditLog(ro)
  assert.equal(a.dirPath, '/tmp/.tm-guard')
  assert.equal(a.path, join('/tmp/.tm-guard', 'audit.jsonl'))
  chmodSync(ro, 0o755)
})

test('record: append failure is non-fatal (warns, does not throw)', () => {
  const d = tmpDir('appendfail')
  const a = new AuditLog(d)
  // destroy the log dir so appendFileSync fails
  rmSync(a.dirPath, { recursive: true, force: true })
  a.record({ tool: 'x', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] }) // must not throw
})

test('readAll: log dir removed -> [] (catch branch)', () => {
  const d = tmpDir('readfail')
  const a = new AuditLog(d)
  a.record({ tool: 'x', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  rmSync(a.dirPath, { recursive: true, force: true })
  assert.deepEqual(a.readAll(), [])
})

test('readAll: logPath is a directory -> [] (readFileSync catch)', () => {
  const d = tmpDir('isdir')
  const a = new AuditLog(d)
  a.record({ tool: 'x', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  // replace the log file with a directory: existsSync passes, readFileSync throws EISDIR
  rmSync(a.path)
  mkdirSync(a.path)
  assert.deepEqual(a.readAll(), [])
})

test('clear: write failure is ignored (does not throw)', () => {
  const d = tmpDir('clearfail')
  const a = new AuditLog(d)
  a.record({ tool: 'x', category: 'read', decision: 'allow', reason: 'r', targetPaths: [] })
  rmSync(a.dirPath, { recursive: true, force: true })
  a.clear() // must not throw
})

test('rotation: emits a runtime log line ([tm-guard] audit rotated …)', () => {
  const d = tmpDir('rotlog')
  const a = new AuditLog(d, { maxBytes: 1024 }) // tiny threshold -> fast rotate
  const captured: string[] = []
  const origWarn = console.warn
  console.warn = (m: unknown, ...rest: unknown[]) => {
    captured.push(String(m) + (rest.length ? ' ' + rest.map(String).join(' ') : ''))
  }
  try {
    let rotated = false
    for (let i = 0; i < 500 && !rotated; i++) {
      a.record({
        tool: 'bash', category: 'read', decision: 'allow',
        reason: 'r'.repeat(96), targetPaths: [],
      })
      rotated = captured.some((s) => s.includes('audit rotated'))
    }
    // The file really rotated (log line matches observable state).
    assert.equal(rotated, true, 'rotation should emit [tm-guard] audit rotated …')
    assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.1')), true)
    const line = captured.find((s) => s.includes('audit rotated'))!
    // First rotation evicts nothing (the window has not filled yet): the line
    // must say so explicitly instead of claiming a deletion that never happened.
    assert.match(line, /\[tm-guard\] audit rotated → \.1; oldest generation beyond 5 retained \(≈1 KiB\/file, 100 MiB cap\), no file evicted yet — retention window just shifted \(deletion starts once it fills\)/)
  } finally {
    console.warn = origWarn
  }
})

test('rotation: host-injected onRotate callback receives structured info (no console)', () => {
  const d = tmpDir('rotcb')
  const infos: unknown[] = []
  // Disable the console fallback by injecting a callback that does not log.
  const a = new AuditLog(d, { maxBytes: 1024 }, (info) => { infos.push(info) })
  let rotated = false
  for (let i = 0; i < 500 && !rotated; i++) {
    a.record({
      tool: 'bash', category: 'read', decision: 'allow',
      reason: 'r'.repeat(96), targetPaths: [],
    })
    rotated = infos.length > 0
  }
  assert.equal(rotated, true, 'rotation should invoke onRotate')
  assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.1')), true)
  const info = infos[infos.length - 1] as {
    retainFiles: number; perFile: string; totalMiB: number; rotatedCount: number; evicted: number
  }
  assert.equal(info.retainFiles, 5)
  assert.match(info.perFile, /1 KiB/)
  assert.equal(info.totalMiB, 100)
  assert.ok(info.rotatedCount >= 1)
  assert.equal(typeof info.evicted, 'number', 'RotateInfo must carry evicted')
})

test('rotation: maxBytes:0 disables rotation entirely (auditMaxBytes:0 contract)', () => {
  const d = tmpDir('rot0')
  const a = new AuditLog(d, { maxBytes: 0 }) // the documented "keep all" switch
  assert.equal(a.maybeRotate(), false, 'maybeRotate with maxBytes:0 must return false')
  for (let i = 0; i < 200; i++) {
    a.record({
      tool: 'bash', category: 'read', decision: 'allow',
      reason: 'r'.repeat(256), targetPaths: [],
    })
  }
  assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.1')), false,
    'no rotation generation may appear while rotation is disabled')
  assert.ok(a.readAll().length >= 200, 'all records must stay in the live file')
})

test('rotation: negative maxBytes also disables rotation (guard is >0)', () => {
  const d = tmpDir('rotneg')
  const a = new AuditLog(d, { maxBytes: -1 })
  assert.equal(a.maybeRotate(), false, 'maybeRotate with negative maxBytes must return false')
  for (let i = 0; i < 50; i++) {
    a.record({
      tool: 'bash', category: 'read', decision: 'allow',
      reason: 'r'.repeat(128), targetPaths: [],
    })
  }
  assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.1')), false)
})

test('rotation: DEFAULT config keeps everything (auditMaxBytes defaults to 0)', () => {
  const d = tmpDir('rotdef')
  const a = new AuditLog(d) // DEFAULT_ROTATION → AUDIT_DEFAULTS.maxBytes = 0 (keep-all)
  assert.equal(a.maybeRotate(), false, 'default config must not rotate (maxBytes defaults to 0)')
  for (let i = 0; i < 300; i++) {
    a.record({
      tool: 'bash', category: 'read', decision: 'allow',
      reason: 'r'.repeat(256), targetPaths: [],
    })
  }
  assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.1')), false,
    'no rotation generation may appear under default config')
  assert.ok(a.readAll().length >= 300, 'all records must stay in the live file under default config')
})

test('rotation: evicted=1 once the window fills — oldest generation deleted, line says so', () => {
  const d = tmpDir('rotevict')
  const a = new AuditLog(d, { maxBytes: 1024, retainFiles: 3 })
  // Pre-seed the oldest generation so the FIRST rotation evicts it.
  writeFileSync(join(a.dirPath, 'audit.jsonl.3'), 'older\n', 'utf8')
  const captured: string[] = []
  const origWarn = console.warn
  console.warn = (m: unknown, ...rest: unknown[]) => {
    captured.push(String(m) + (rest.length ? ' ' + rest.map(String).join(' ') : ''))
  }
  try {
    let rotated = false
    for (let i = 0; i < 500 && !rotated; i++) {
      a.record({
        tool: 'bash', category: 'read', decision: 'allow',
        reason: 'r'.repeat(96), targetPaths: [],
      })
      rotated = captured.some((s) => s.includes('audit rotated'))
    }
    assert.equal(rotated, true, 'rotation should fire')
    assert.equal(existsSync(join(a.dirPath, 'audit.jsonl.3')), false,
      'the evicted oldest generation must be gone')
    const line = captured.find((s) => s.includes('audit rotated'))!
    assert.match(line, /physically deleted 1 generation\(s\) — forensics reach back only this far/,
      'window-full rotation must report the actual deletion')
  } finally {
    console.warn = origWarn
  }
})

test('rotation: total-ceiling (backstop) deletions are counted into evicted', () => {
  const d = tmpDir('rotevictcap')
  // Pre-seed an oversized generation so the FIRST rotation's size backstop
  // (not the window shift) does the deleting: retainFiles=3, .3 absent so
  // step1 evicts 0; the seeded .1 shifts to .2 and the ceiling evicts it.
  const guardDir = join(d, '.tm-guard')
  mkdirSync(guardDir, { recursive: true })
  writeFileSync(join(guardDir, 'audit.jsonl.1'), 'x'.repeat(2048), 'utf8')
  const a = new AuditLog(d, { maxBytes: 1024, retainFiles: 3, totalMaxBytes: 1024 })
  const captured: string[] = []
  const origWarn = console.warn
  console.warn = (m: unknown, ...rest: unknown[]) => {
    captured.push(String(m) + (rest.length ? ' ' + rest.map(String).join(' ') : ''))
  }
  try {
    let rotated = false
    for (let i = 0; i < 500 && !rotated; i++) {
      a.record({
        tool: 'bash', category: 'read', decision: 'allow',
        reason: 'r'.repeat(96), targetPaths: [],
      })
      rotated = captured.some((s) => s.includes('audit rotated'))
    }
    assert.equal(rotated, true, 'rotation should fire')
    assert.equal(existsSync(join(guardDir, 'audit.jsonl.2')), false,
      'the ceiling-evicted generation must be gone')
    const line = captured.find((s) => s.includes('audit rotated'))!
    assert.match(line, /physically deleted 1 generation\(s\) — forensics reach back only this far/,
      'backstop deletions must be reported as real evictions')
  } finally {
    console.warn = origWarn
  }
})
