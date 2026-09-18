// End-to-end rollback test — Time Machine backup strategy (tm-backup).
//
// This verifies the automated restore path that works WITHOUT root: copying a
// file out of a completed, browsable Time Machine backup (Strategy 1).
//
// Preconditions — the test SKIPs (exit 0) when they are not met:
//   - Full Disk Access for the app running this test (System Settings →
//     Privacy & Security → Full Disk Access), otherwise the backup store is
//     unreadable ("Operation not permitted").
//   - At least one completed Time Machine backup containing the test file
//     (default: $TM_TEST_FILE, else /tmp/tm-guard-temp/test.txt).
//     TM recovers files that were backed up — brand-new files are handled by
//     the git layer instead (see test-git-rollback.mts).
//
//   node test-rollback.mts
//
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { listBrowsableBackups, rollbackPath } from './src/tm.ts'

const target = process.env.TM_TEST_FILE ?? '/tmp/tm-guard-temp/test.txt'

const backups = listBrowsableBackups()
if (backups.length === 0) {
  console.log('SKIP: no browsable Time Machine backup found.')
  console.log('Run after a backup cycle completes to the TM disk and Full Disk')
  console.log('Access is granted to the app running this test.')
  process.exit(0)
}

const latest = backups[backups.length - 1]
const backupSrc = `${latest.dataRoot}${target}`
if (!existsSync(backupSrc)) {
  console.log(`SKIP: ${target} is not in the latest browsable backup (${latest.date}).`)
  console.log('The test subject must exist in a completed backup — Time Machine')
  console.log('can only recover files that were backed up.')
  process.exit(0)
}

// Deterministic start state: make the local file match the backed-up version,
// so the expected restore result is unambiguous regardless of local drift.
mkdirSync(dirname(target), { recursive: true })
const backupVersion = readFileSync(backupSrc, 'utf8')
writeFileSync(target, backupVersion)

// Corrupt the local copy
writeFileSync(target, 'CORRUPTED-BY-TEST\n')
console.log('corrupted:', JSON.stringify(readFileSync(target, 'utf8')))

// Restore from the browsable backup
const result = await rollbackPath(target, latest.date)
const after = readFileSync(target, 'utf8')

console.log('backup used :', latest.date)
console.log('rollback    :', result.success, `(${result.strategy})`)
console.log('file after  :', JSON.stringify(after))

if (result.success && result.strategy === 'tm-backup' && after === backupVersion) {
  console.log('\n✅ TM-BACKUP ROLLBACK WORKS — real backup, real restore')
  process.exit(0)
} else {
  console.log('\n❌ FAILED:')
  console.log(result.message.split('\n').slice(0, 8).join('\n'))
  process.exit(1)
}
