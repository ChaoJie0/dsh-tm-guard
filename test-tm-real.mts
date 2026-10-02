// Real Time Machine integration tests — require an actual browsable TM backup
// volume mounted under /Volumes (the machine has one: /Volumes/SD).
// Strategy: real backup tree for existsSync (source really exists), but the
// cp step is injected so nothing is actually copied (zero side effects).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readdirSync } from 'node:fs'
import { rollbackPath, getTmHealth, __setExecOverride } from './src/tm.ts'

const MANIFEST = '/Volumes/SD/backup_manifest.plist'
const HOST = '/Volumes/SD'
const TARGET = '/Users/zero/Claude Code/自治/README.md' // exists in backup AND locally

function haveRealBackup(): boolean {
  // The guard must check what the tests actually depend on: the manifest
  // existing AND the backup tree being readable. Without FDA, /Volumes/SD
  // stats fine but readdirSync throws EPERM — manifest-exists alone then
  // turns these tests into failures instead of skips.
  if (!existsSync(MANIFEST)) return false
  try {
    readdirSync(HOST)
    return true
  } catch {
    return false
  }
}

test('real TM: browse finds the SD backup and rollback succeeds via tm-backup', async (t) => {
  if (!haveRealBackup()) return t.skip('no browsable TM backup on this machine')
  const called: Array<{ file: string; args: string[] }> = []
  __setExecOverride(async (file, args) => {
    called.push({ file, args })
    if (file === '/bin/cp') return { stdout: '' }
    return { stdout: '' }
  })
  try {
    const r = await rollbackPath(TARGET)
    assert.equal(r.success, true, `message: ${r.message}`)
    assert.equal(r.strategy, 'tm-backup', `message: ${r.message}`)
    assert.match(r.snapshotUsed ?? '', /^\d{4}-\d{2}-\d{2}-\d{6}$/, `snapshot: ${r.snapshotUsed}`)
    assert.match(r.message, /Time Machine backup/, r.message)
    assert.deepEqual(r.restoredPaths, [TARGET])
    const cp = called.find((c) => c.file === '/bin/cp')
    assert.ok(cp, 'cp should have been invoked')
    assert.equal(cp!.args[0], '-R')
    assert.ok(cp!.args[1].startsWith('/Volumes/SD/'), `src should be under SD: ${cp!.args[1]}`)
    assert.ok(cp!.args[1].includes('.previous'), `src should be a completed backup: ${cp!.args[1]}`)
    assert.equal(cp!.args[2], TARGET)
  } finally {
    __setExecOverride(null)
  }
})

test('real TM: cp failure falls through to manual guidance', async (t) => {
  if (!haveRealBackup()) return t.skip('no browsable TM backup on this machine')
  __setExecOverride(async (file) => {
    if (file === '/bin/cp') throw new Error('injected cp failure')
    return { stdout: '' }
  })
  try {
    const r = await rollbackPath(TARGET)
    assert.equal(r.success, false, `message: ${r.message}`)
    assert.notEqual(r.strategy, 'tm-backup', `strategy: ${r.strategy}`)
    assert.match(r.message, /could not be copied automatically/, r.message)
  } finally {
    __setExecOverride(null)
  }
})

test('real TM: backup exists but target absent from backup → "does not exist" guidance', async (t) => {
  if (!haveRealBackup()) return t.skip('no browsable TM backup on this machine')
  const never = `/tmp/tm-real-never-${Date.now()}.txt`
  __setExecOverride(async () => ({ stdout: '' }))
  try {
    const r = await rollbackPath(never)
    assert.equal(r.success, false, `message: ${r.message}`)
    assert.match(r.message, /does not exist in the latest backup/, r.message)
  } finally {
    __setExecOverride(null)
  }
})

test('real TM: getTmHealth reports the mounted backup', async (t) => {
  if (!haveRealBackup()) return t.skip('no browsable TM backup on this machine')
  const h = await getTmHealth(['/Users/zero/Claude Code/自治'])
  assert.equal(typeof h.healthy, 'boolean')
  assert.equal(typeof h.destinationConfigured, 'boolean')
  assert.equal(typeof h.hasSnapshots, 'boolean')
  assert.equal(typeof h.snapshotCount, 'number')
  assert.equal(typeof h.workspaceProtected, 'boolean')
  assert.ok(h.destinationConfigured, 'SD destination should be configured')
})
