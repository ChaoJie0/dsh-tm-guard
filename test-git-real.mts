// Real-git rollback drill: the plugin's rollback path is instructions to the
// agent (`git reset --hard HEAD` + `git clean -fd`), so we verify the exact
// commands the plugin emits actually restore a workspace on a real repo.
// Covers: tracked-edit revert, untracked-file removal, checkpoint-pinned
// revert (most recent checkpoint commit is HEAD when the plugin commits
// before writes).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, realpathSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { ensureGitBaseline, commitCheckpoint, repoRoot } from './src/git.ts'

function freshRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'tm-git-real-'))
  execFileSync('git', ['init', '-q'], { cwd: dir })
  execFileSync('git', ['config', 'user.email', 't@t'], { cwd: dir })
  execFileSync('git', ['config', 'user.name', 't'], { cwd: dir })
  return dir
}

test('ensureGitBaseline on a real repo creates the plugin baseline commit', async () => {
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 'a.txt'), 'v1')
    const r = await ensureGitBaseline(dir)
    assert.equal(r.ok, true, JSON.stringify(r))
    // baseline committed: working tree clean
    const status = execFileSync('git', ['status', '--porcelain'], { cwd: dir, encoding: 'utf8' })
    assert.equal(status.trim(), '')
    const files = execFileSync('git', ['ls-files'], { cwd: dir, encoding: 'utf8' })
    assert.ok(files.includes('a.txt'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('plugin rollback instructions: reset --hard restores tracked edits', async () => {
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 't.txt'), 'v1')
    await ensureGitBaseline(dir)
    writeFileSync(join(dir, 't.txt'), 'v2-crafted')
    // Exact commands the plugin tells the agent to run on failure:
    execFileSync('git', ['reset', '--hard', 'HEAD'], { cwd: dir })
    assert.equal(readFileSync(join(dir, 't.txt'), 'utf8'), 'v1')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('plugin rollback instructions: clean -fd removes post-baseline files', async () => {
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 't.txt'), 'v1')
    await ensureGitBaseline(dir)
    writeFileSync(join(dir, 'crafted-new.txt'), 'x') // created after baseline
    execFileSync('git', ['clean', '-fd'], { cwd: dir })
    assert.equal(existsSync(join(dir, 'crafted-new.txt')), false)
    // tracked file untouched by clean
    assert.equal(readFileSync(join(dir, 't.txt'), 'utf8'), 'v1')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('checkpoint pinning: reset --hard returns to the latest checkpoint commit', async () => {
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 't.txt'), 'v1')
    await ensureGitBaseline(dir)          // baseline commit (HEAD)
    writeFileSync(join(dir, 't.txt'), 'v2')
    await commitCheckpoint(dir, 'checkpoint-1')  // HEAD = checkpoint-1
    writeFileSync(join(dir, 't.txt'), 'v3')
    writeFileSync(join(dir, 'more.txt'), 'm')
    execFileSync('git', ['reset', '--hard', 'HEAD'], { cwd: dir })
    execFileSync('git', ['clean', '-fd'], { cwd: dir }) // plugin instructions run both
    assert.equal(readFileSync(join(dir, 't.txt'), 'utf8'), 'v2')
    assert.equal(existsSync(join(dir, 'more.txt')), false)
    assert.equal(execFileSync('git', ['log', '--oneline', '-2'], { cwd: dir, encoding: 'utf8' }).split('\n').filter(Boolean).length, 2) // base + checkpoint
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('repoRoot walks up to the enclosing repo', async () => {
  const dir = freshRepo()
  try {
    const sub = join(dir, 'a', 'b')
    execFileSync('mkdir', ['-p', sub])
    assert.equal(await repoRoot(sub), realpathSync(dir)) // macOS /var → /private/var symlink
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
