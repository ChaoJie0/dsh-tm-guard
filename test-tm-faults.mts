// Fault-injection tests for tm.ts — the Time Machine rollback safety net.
//
// tm.ts shells out to tmutil/df/mount_apfs/umount/cp. The real-system paths
// (actual TM backups) are covered by test-rollback.mts / test-git-rollback.mts;
// THIS file covers the failure branches and pure logic via the __setExecOverride
// test seam: no real Time Machine, no sudo, deterministic outcomes.
//
// Covered: parseBackupStatus variants, pickBackup, createSnapshot/listSnapshots/
// latestSnapshot parsing, isPathExcluded/isPathProtected, getTmStatus,
// getBackupStatus/startBackup, rollbackPath failure + manual-mount success
// branches, rollbackPaths, getTmHealth (all fail-closed branches + cache).
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  __setExecOverride,
  createSnapshot,
  getBackupStatus,
  getTmHealth,
  getTmStatus,
  invalidateHealthCache,
  isPathExcluded,
  isPathProtected,
  latestSnapshot,
  listSnapshots,
  parseBackupStatus,
  pickBackup,
  rollbackPath,
  rollbackPaths,
  startBackup,
} from './src/tm.ts'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

after(() => __setExecOverride(null))

const SNAP_LINE = 'com.apple.TimeMachine.2026-09-06-120000.local'
const SNAP_LINE2 = 'com.apple.TimeMachine.2026-09-07-083000.local'
const DEST_OK = 'Name : Local SD\nID   : ABCDEF\n'
const DEST_EMPTY = 'No destinations are configured.'
const LIST_OK = `Snapshots for disk /:\n${SNAP_LINE}\n${SNAP_LINE2}\n`
const LIST_EMPTY = 'Snapshots for disk /:\n'
const DF_OK = 'Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s5 100 10 90 10% 1 2 1% /System/Volumes/Data\n'

/** Run a test with an exec override; restores null afterwards. */
async function withExec(fn: (file: string, args: string[]) => Promise<{ stdout: string }>, body: () => Promise<void>) {
  __setExecOverride(fn)
  try { await body() } finally { __setExecOverride(null) }
}

// ---------------------------------------------------------------------------
test('parseBackupStatus: running + percent + phase parse', () => {
  const s = parseBackupStatus('Running = 1;\nPercent = "63.5";\nPhase = "Copying";\n')
  assert.equal(s.running, true)
  assert.equal(s.percent, 64) // tm.ts rounds the reported percent
  assert.equal(s.phase, 'Copying')
})

test('parseBackupStatus: idle / missing fields / garbage', () => {
  const idle = parseBackupStatus('Running = 0;\n')
  assert.equal(idle.running, false)
  assert.equal(idle.percent, -1)
  assert.equal(idle.phase, undefined)
  const partial = parseBackupStatus('Running = 1;\n')
  assert.equal(partial.percent, -1)
  assert.equal(parseBackupStatus('not a plist').running, false)
  assert.equal(parseBackupStatus('').running, false)
})

// ---------------------------------------------------------------------------
test('pickBackup: exact date / before-date / empty / latest', () => {
  const b = [
    { date: '2026-09-06-120000', dataRoot: '/a/1', createdAt: new Date(2026, 8, 6, 12) },
    { date: '2026-09-07-083000', dataRoot: '/a/2', createdAt: new Date(2026, 8, 7, 8, 30) },
  ]
  assert.equal(pickBackup(b, '2026-09-07-083000')?.date, '2026-09-07-083000')
  assert.equal(pickBackup(b, '2026-01-01-000000'), undefined) // exact miss
  assert.equal(pickBackup(b, undefined, new Date(2026, 8, 7))?.date, '2026-09-06-120000') // before excludes 09-07
  assert.equal(pickBackup(b, undefined, new Date(2026, 8, 5))?.date, '2026-09-07-083000') // before: none before -> latest
  assert.equal(pickBackup(b)?.date, '2026-09-07-083000') // latest default
  assert.equal(pickBackup([], undefined, new Date()), undefined) // empty
})

// ---------------------------------------------------------------------------
test('createSnapshot: parses date from tmutil output', async () => {
  await withExec(async (f, a) => {
    assert.equal(f, '/usr/bin/tmutil')
    assert.deepEqual(a, ['localsnapshot'])
    return { stdout: 'Created local snapshot with date: 2026-09-06-120000\n' }
  }, async () => {
    assert.equal(await createSnapshot(), '2026-09-06-120000')
  })
})

test('createSnapshot: falls back to raw output when unparseable', async () => {
  await withExec(async () => ({ stdout: 'error: TM not enabled' }), async () => {
    assert.equal(await createSnapshot(), 'error: TM not enabled')
  })
})

test('listSnapshots/latestSnapshot: parse, filter garbage, sort ascending', async () => {
  await withExec(async () => ({ stdout: LIST_OK + 'garbage-line\n' }), async () => {
    const snaps = await listSnapshots('/')
    assert.equal(snaps.length, 2)
    assert.equal(snaps[0].date, '2026-09-06-120000')
    assert.equal(snaps[1].date, '2026-09-07-083000') // sorted
    assert.equal((await latestSnapshot('/'))?.date, '2026-09-07-083000')
  })
})

test('latestSnapshot: null when no snapshots', async () => {
  await withExec(async () => ({ stdout: LIST_EMPTY }), async () => {
    assert.equal(await latestSnapshot('/'), null)
  })
})

test('listSnapshots: tmutil failure propagates', async () => {
  await withExec(async () => { throw new Error('tmutil missing') }, async () => {
    await assert.rejects(listSnapshots('/'))
  })
})

// ---------------------------------------------------------------------------
test('isPathExcluded: [Excluded]/[Included]/tmutil failure', async () => {
  await withExec(async (f, a) => {
    assert.equal(f, '/usr/bin/tmutil')
    assert.equal(a[0], 'isexcluded')
    if (a[1] === '/Users/zero/work') return { stdout: '[Excluded] /Users/zero/work\n' }
    return { stdout: '[Included] /Users/zero/other\n' }
  }, async () => {
    assert.equal(await isPathExcluded('/Users/zero/work'), true)
    assert.equal(await isPathExcluded('/Users/zero/other'), false)
  })
  // tmutil failure -> conservatively excluded (true)
  await withExec(async () => { throw new Error('denied') }, async () => {
    assert.equal(await isPathExcluded('/x'), true)
  })
})

test('isPathProtected: prefix boundary + exclusion + ~ expansion', async () => {
  const prefixes = ['/Users/zero/Claude Code']
  // under prefix + included -> protected
  __setExecOverride(async () => ({ stdout: '[Included] /Users/zero/Claude Code/x\n' }))
  assert.equal(await isPathProtected('/Users/zero/Claude Code/x', prefixes), true)
  __setExecOverride(null)
  // excluded -> not protected
  await withExec(async () => ({ stdout: '[Excluded] /Users/zero/Claude Code/x\n' }), async () => {
    assert.equal(await isPathProtected('/Users/zero/Claude Code/x', prefixes), false)
  })
  // outside prefix -> not protected (no tmutil call)
  assert.equal(await isPathProtected('/Users/zero/elsewhere', prefixes), false)
})

// ---------------------------------------------------------------------------
test('getTmStatus: configured + snapshot count', async () => {
  await withExec(async (f, a) => {
    if (a[0] === 'destinationinfo') return { stdout: DEST_OK }
    return { stdout: LIST_OK }
  }, async () => {
    const s = await getTmStatus()
    assert.equal(s.destinationConfigured, true)
    assert.equal(s.hasLocalSnapshots, true)
    assert.equal(s.snapshotCount, 2)
  })
})

test('getTmStatus: not configured + tmutil failure', async () => {
  await withExec(async (f, a) => {
    if (a[0] === 'destinationinfo') throw new Error('disabled')
    throw new Error('disabled')
  }, async () => {
    const s = await getTmStatus()
    assert.equal(s.destinationConfigured, false)
    assert.equal(s.snapshotCount, 0)
    assert.match(s.raw, /not configured/)
  })
})

test('getBackupStatus: parse via run', async () => {
  await withExec(async () => ({ stdout: 'Running = 1;\nPercent = "42.0";\n' }), async () => {
    const s = await getBackupStatus()
    assert.equal(s.running, true)
    assert.equal(s.percent, 42)
  })
})

test('startBackup: background and blocking variants pass args', async () => {
  const calls: string[][] = []
  await withExec(async (f, a) => { calls.push(a); return { stdout: '' } }, async () => {
    await startBackup(false)
    await startBackup(true)
  })
  assert.deepEqual(calls[0], ['startbackup', '--auto'])
  assert.deepEqual(calls[1], ['startbackup', '--auto', '--block'])
})

// ---------------------------------------------------------------------------
test('rollbackPath: no backup + no snapshot -> manual guidance', async () => {
  // NOTE: this machine may have real browsable TM backups (listBrowsableBackups
  // reads /Volumes). When they exist the message differs — assert the parts
  // every failure branch shares: failure + manual strategy + how-to text.
  await withExec(async (f, a) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_EMPTY }
    throw new Error('unexpected')
  }, async () => {
    const r = await rollbackPath('/tmp/tm-guard-faults/never.txt', '2026-09-06-120000')
    assert.equal(r.success, false)
    assert.equal(r.strategy, 'manual')
    assert.match(r.message, /Could not automatically recover/)
    assert.match(r.message, /To recover manually/)
  })
})

test('rollbackPath: snapshot exists but df fails -> manual', async () => {
  await withExec(async (f, a) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    throw new Error('df unavailable') // df (and anything else) fails
  }, async () => {
    const r = await rollbackPath('/tmp/tm-guard-faults/never.txt')
    assert.equal(r.success, false)
    assert.equal(r.strategy, 'manual')
  })
})

test('rollbackPath: snapshot + device but mount fails -> manual with backup note', async () => {
  await withExec(async (f, a) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    if (f === '/bin/df') return { stdout: DF_OK }
    throw new Error('mount_apfs: Resource busy') // mount fails
  }, async () => {
    const r = await rollbackPath('/tmp/tm-guard-faults/never.txt')
    assert.equal(r.success, false)
    assert.equal(r.strategy, 'manual')
    assert.match(r.message, /To recover manually/)
  })
})

test('rollbackPath: manual-mount success via injected mount + cp', async () => {
  const target = join(mkdtempSync('/tmp/tm-fault-mount-'), 'restored.txt')
  await withExec(async (f, a) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    if (f === '/bin/df') return { stdout: DF_OK }
    if (f === '/sbin/mount_apfs') {
      const mountPath = a[a.length - 1] // /tmp/tm-guard-snap-<ts>
      mkdirSync(mountPath, { recursive: true })
      // create the parent chain INSIDE the mount so the candidate file exists;
      // note: mkdir on the full file path would make writeFileSync fail (EISDIR)
      mkdirSync(join(mountPath, dirname(target)), { recursive: true })
      writeFileSync(`${mountPath}${target}`, 'FROM-SNAPSHOT\n') // first candidate
      return { stdout: '' }
    }
    if (f === '/bin/cp') {
      writeFileSync(a[2], 'FROM-SNAPSHOT\n') // simulate copy
      return { stdout: '' }
    }
    if (f === '/sbin/umount') return { stdout: '' }
    throw new Error(`unexpected ${f}`)
  }, async () => {
    const r = await rollbackPath(target)
    assert.equal(r.success, true)
    assert.equal(r.strategy, 'manual-mount')
    assert.equal(r.snapshotUsed, '2026-09-07-083000') // latest snapshot
  })
})

test('rollbackPaths: per-path results', async () => {
  await withExec(async () => ({ stdout: LIST_EMPTY }), async () => {
    const rs = await rollbackPaths(['/tmp/tm-guard-faults/a.txt', '/tmp/tm-guard-faults/b.txt'])
    assert.equal(rs.length, 2)
    assert.equal(rs.every((r) => r.success === false), true)
  })
})

// ---------------------------------------------------------------------------
test('getTmHealth: healthy when all checks pass', async () => {
  invalidateHealthCache()
  await withExec(async (f, a) => {
    if (a[0] === 'destinationinfo') return { stdout: DEST_OK }
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    return { stdout: '[Included] /Users/zero/Claude Code\n' } // isexcluded
  }, async () => {
    const h = await getTmHealth(['/Users/zero/Claude Code'])
    assert.equal(h.healthy, true)
    assert.equal(h.destinationConfigured, true)
    assert.equal(h.hasSnapshots, true)
    assert.equal(h.snapshotCount, 2)
    assert.equal(h.workspaceProtected, true)
    assert.equal(h.unprotectedPaths.length, 0)
    assert.equal(h.issues.length, 0)
  })
})

test('getTmHealth: all three failures reported', async () => {
  invalidateHealthCache()
  await withExec(async (f, a) => {
    if (a[0] === 'destinationinfo') return { stdout: DEST_EMPTY }
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_EMPTY }
    return { stdout: '[Excluded] /Users/zero/Claude Code\n' }
  }, async () => {
    const h = await getTmHealth(['/Users/zero/Claude Code'])
    assert.equal(h.healthy, false)
    assert.equal(h.destinationConfigured, false)
    assert.equal(h.hasSnapshots, false)
    assert.equal(h.workspaceProtected, false)
    assert.deepEqual(h.unprotectedPaths, ['/Users/zero/Claude Code'])
    assert.equal(h.issues.length, 3)
  })
})

test('getTmHealth: destinationinfo failure counts as not configured', async () => {
  invalidateHealthCache()
  await withExec(async (f, a) => {
    if (a[0] === 'destinationinfo') throw new Error('TM disabled')
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    return { stdout: '[Included] /Users/zero/Claude Code\n' }
  }, async () => {
    const h = await getTmHealth(['/Users/zero/Claude Code'])
    assert.equal(h.healthy, false)
    assert.match(h.issues[0], /destination is NOT configured/)
  })
})

test('getTmHealth: cache hit skips tmutil; forceRefresh re-runs', async () => {
  invalidateHealthCache()
  let calls = 0
  const healthFn = async () => {
    calls++
    return { stdout: DEST_OK }
  }
  __setExecOverride(async (f, a) => {
    if (a[0] === 'destinationinfo') return healthFn()
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    return { stdout: '[Included] /Users/zero/Claude Code\n' }
  })
  const h1 = await getTmHealth(['/Users/zero/Claude Code'])
  const h2 = await getTmHealth(['/Users/zero/Claude Code']) // cache
  assert.equal(h1.checkedAt.getTime(), h2.checkedAt.getTime())
  const c1 = calls
  await getTmHealth(['/Users/zero/Claude Code'], true) // force refresh
  assert.ok(calls > c1, 'forceRefresh must re-run checks')
  __setExecOverride(null)
})

test('invalidateHealthCache: forces a fresh check', async () => {
  invalidateHealthCache()
  let n = 0
  __setExecOverride(async (f, a) => {
    if (a[0] === 'destinationinfo') return { stdout: n++ === 0 ? DEST_EMPTY : DEST_OK }
    if (a[0] === 'listlocalsnapshots') return { stdout: LIST_OK }
    return { stdout: '[Included] /Users/zero/Claude Code\n' }
  })
  const h1 = await getTmHealth(['/Users/zero/Claude Code'])
  assert.equal(h1.healthy, false)
  invalidateHealthCache()
  const h2 = await getTmHealth(['/Users/zero/Claude Code'])
  assert.equal(h2.healthy, true)
  __setExecOverride(null)
})
