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
  appendFileSync, chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync,
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
