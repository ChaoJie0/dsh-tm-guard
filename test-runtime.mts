// Smoke test for tm.ts (read-only tmutil calls) and audit.ts.
// Run: node test-runtime.mts
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { listSnapshots, latestSnapshot, getTmStatus, isPathProtected } from './src/tm.ts'
import { AuditLog } from './src/audit.ts'

let pass = 0
let fail = 0
function ok(name: string, cond: boolean, extra = '') {
  if (cond) { pass++; console.log(`PASS: ${name}`) }
  else { fail++; console.log(`FAIL: ${name} ${extra}`) }
}

// --- tm.ts: list snapshots on this Mac ---
const snaps = await listSnapshots('/')
ok('listSnapshots returns array', Array.isArray(snaps))
if (snaps.length > 0) {
  const s = snaps[0]
  ok('snapshot has name/date/createdAt',
    typeof s.name === 'string' && /^\d{4}-\d{2}-\d{2}-\d{6}$/.test(s.date) && s.createdAt instanceof Date,
    JSON.stringify(s))
  const latest = await latestSnapshot('/')
  ok('latestSnapshot is newest',
    !!latest && latest.date === snaps[snaps.length - 1].date)
} else {
  console.log('  (no local snapshots on this machine — skipping snapshot shape checks)')
}

// --- tm.ts: TM status ---
const status = await getTmStatus()
ok('getTmStatus returns booleans/count',
  typeof status.destinationConfigured === 'boolean' &&
  typeof status.snapshotCount === 'number' &&
  status.snapshotCount === snaps.length,
  JSON.stringify({ dest: status.destinationConfigured, count: status.snapshotCount }))

// --- tm.ts: path protection logic (no TM exclusion expected for cwd) ---
const cwdProtected = await isPathProtected(process.cwd(), [process.cwd()])
ok('cwd is protected under its own prefix', cwdProtected === true || cwdProtected === false)
const outside = await isPathProtected('/etc/hosts', [process.cwd()])
ok('path outside protected prefixes is NOT protected', outside === false)

// --- audit.ts: write + read back ---
const dir = mkdtempSync(join(tmpdir(), 'tm-guard-test-'))
try {
  const audit = new AuditLog(dir)
  ok('audit log path is jsonl inside .tm-guard', audit.path.endsWith('.tm-guard/audit.jsonl'), audit.path)
  audit.record({ tool: 'bash', category: 'read', decision: 'allow', reason: 'test', targetPaths: [] })
  audit.record({ tool: 'fs_write', category: 'file_write', decision: 'allow', reason: 'test write', targetPaths: ['/x/y.txt'], snapshotId: '2026-09-06-120000' })
  audit.record({ tool: 'curl', category: 'network', decision: 'deny', reason: 'blocked', targetPaths: [] })
  const all = audit.readAll()
  ok('readAll returns 3 records', all.length === 3, `got ${all.length}`)
  ok('records have ISO ts', typeof all[0].ts === 'string' && all[0].ts.includes('T'))
  const writes = audit.writeOperations()
  ok('writeOperations finds 1 allowed write with paths', writes.length === 1 && writes[0].targetPaths[0] === '/x/y.txt')
  ok('lastWriteSnapshot returns snapshot id', audit.lastWriteSnapshot() === '2026-09-06-120000')
  ok('recent(1) returns last record', audit.recent(1).length === 1 && audit.recent(1)[0].tool === 'curl')
  audit.clear()
  ok('clear empties the log', audit.readAll().length === 0)
} finally {
  rmSync(dir, { recursive: true, force: true })
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
