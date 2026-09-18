// Git-baseline rollback test — the instant, root-free, offline rollback layer.
// No permissions needed. Covers: baseline auto-init (ensureGitBaseline),
// `git reset --hard` (restore corrupted tracked files), `git clean -fd`
// (remove files created after the baseline).
//
//   node test-git-rollback.mts
//
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { ensureGitBaseline } from './src/git.ts'

const dir = mkdtempSync('/tmp/git-rb-')
let failed = false
try {
  const file = join(dir, 'sample.txt')
  writeFileSync(file, 'version-1-GOOD\n')

  // 1. Plugin-level baseline enforcement (the same path the gate runs)
  const r = await ensureGitBaseline(dir)
  if (!r.ok) throw new Error(`baseline failed: ${r.reason}`)
  console.log('PASS: baseline ensured (git init + .gitignore + baseline commit)')

  // 2. Corrupt a tracked file
  writeFileSync(file, 'version-2-CORRUPTED\n')

  // 3. Roll back via git reset --hard (no root, no network, instant)
  execFileSync('git', ['reset', '--hard', 'HEAD'], { cwd: dir })
  const after = readFileSync(file, 'utf8').trim()
  if (after !== 'version-1-GOOD') {
    throw new Error(`git reset --hard did not restore original: got "${after}"`)
  }
  console.log('PASS: git reset --hard restored corrupted tracked file')

  // 4. Remove a file created after the baseline
  const extra = join(dir, 'new-file.txt')
  writeFileSync(extra, 'junk\n')
  execFileSync('git', ['clean', '-fd'], { cwd: dir })
  if (existsSync(extra)) {
    throw new Error('git clean -fd did not remove the new file')
  }
  console.log('PASS: git clean -fd removed post-baseline file')

  console.log('\n✅ GIT ROLLBACK LAYER WORKS — 3/3')
} catch (err) {
  failed = true
  console.error('❌ FAILED:', err instanceof Error ? err.message : err)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
process.exit(failed ? 1 : 0)
