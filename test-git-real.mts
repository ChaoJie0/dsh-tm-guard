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
import { ensureGitBaseline, commitCheckpoint, repoRoot, nearestExistingAncestor } from './src/git.ts'

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

test('nearestExistingAncestor returns the dir itself when it exists', () => {
  const dir = freshRepo()
  try {
    // lexical helper: returns the input form, does not resolve symlinks
    assert.equal(nearestExistingAncestor(dir), dir)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('nearestExistingAncestor walks up to the first existing ancestor', () => {
  const dir = freshRepo()
  try {
    const deep = join(dir, 'a', 'b', 'c')
    // none of a/b/c exist yet
    assert.equal(nearestExistingAncestor(deep), dir)
    // once the top-most segment exists, it becomes the anchor
    execFileSync('mkdir', ['-p', join(dir, 'a')])
    assert.equal(nearestExistingAncestor(deep), join(dir, 'a'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('missing target dir falls back to nearest existing ancestor baseline', async () => {
  // Mirrors the gate fix: `mkdir -p fresh && echo > fresh/f.txt` is decided
  // BEFORE mkdir runs, so fresh/ does not exist yet. The git baseline is
  // anchored at the nearest existing ancestor (the repo root) instead.
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 'seed.txt'), 's')
    await ensureGitBaseline(dir)
    const missing = join(dir, 'fresh', 'nested', 'f.txt') // fresh/ + nested/ absent
    const anchor = nearestExistingAncestor(missing)
    // lexical walk returns the input form; git resolves the real path
    assert.equal(anchor, dir)
    const r = await ensureGitBaseline(anchor)
    assert.equal(r.ok, true, JSON.stringify(r))
    assert.equal(r.root, realpathSync(dir))
    // no premature directory creation by the fallback itself
    assert.equal(existsSync(join(dir, 'fresh')), false)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('concurrent ensureGitBaseline on the same dir both succeed (inflight dedupe)', async () => {
  // The gate runs one gitCheck per write target in Promise.all; after the
  // nearest-ancestor fallback, several targets can anchor on the SAME dir.
  // Without dedupe, concurrent git init + add + commit race on index.lock and
  // one randomly fails.
  const dir = freshRepo()
  try {
    writeFileSync(join(dir, 'seed.txt'), 's')
    const [a, b] = await Promise.all([
      ensureGitBaseline(dir),
      ensureGitBaseline(dir),
    ])
    assert.equal(a.ok, true, JSON.stringify(a))
    assert.equal(b.ok, true, JSON.stringify(b))
    // exactly one baseline commit exists (baseline is idempotent)
    const log = execFileSync('git', ['log', '--oneline'], { cwd: dir, encoding: 'utf8' })
    const commits = log.split('\n').filter(Boolean).length
    assert.equal(commits, 1)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
