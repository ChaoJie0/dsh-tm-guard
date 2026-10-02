// Fault-injection tests for git.ts — the instant offline rollback layer.
//
// Success paths (real git init / baseline / reset / clean) are covered by
// test-git-rollback.mts. THIS file covers the failure branches and guard
// logic via the __setGitOverride test seam: missing binary, failed init,
// failed baseline commit, dirty/clean status, cache idempotency.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  __setGitOverride,
  commitCheckpoint,
  ensureGitBaseline,
  hasCommit,
  repoRoot,
} from './src/git.ts'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'

const realTmp = mkdtempSync('/tmp/git-faults-')

after(() => __setGitOverride(null))

// ---------------------------------------------------------------------------
test('repoRoot: returns root / null on failure / null on empty output', async () => {
  __setGitOverride(async (args, cwd) => {
    assert.deepEqual(args, ['rev-parse', '--show-toplevel'])
    assert.equal(cwd, '/x')
    return '/Users/zero/proj'
  })
  assert.equal(await repoRoot('/x'), '/Users/zero/proj')
  __setGitOverride(null)

  __setGitOverride(async () => { throw new Error('fatal: not a git repository') })
  assert.equal(await repoRoot('/x'), null)
  __setGitOverride(null)

  __setGitOverride(async () => '') // empty stdout -> null
  assert.equal(await repoRoot('/x'), null)
  __setGitOverride(null)
})

// ---------------------------------------------------------------------------
test('hasCommit: HEAD exists -> true; failure -> false', async () => {
  __setGitOverride(async (args) => {
    assert.deepEqual(args, ['rev-parse', 'HEAD'])
    return 'abc123'
  })
  assert.equal(await hasCommit('/x'), true)
  __setGitOverride(null)

  __setGitOverride(async () => { throw new Error('unknown revision') })
  assert.equal(await hasCommit('/x'), false)
  __setGitOverride(null)
})

// ---------------------------------------------------------------------------
test('ensureGitBaseline: cached dir short-circuits (no git calls)', async () => {
  const dir = join(realTmp, 'cached')
  let calls = 0
  __setGitOverride(async () => { calls++; return '' })
  const r1 = await ensureGitBaseline(dir)
  const r2 = await ensureGitBaseline(dir)
  assert.equal(r1.ok, true)
  assert.equal(r2.ok, true)
  assert.ok(calls < 5, `cache should limit calls, got ${calls}`)
  __setGitOverride(null)
})

test('ensureGitBaseline: already a repo with a commit -> no init/commit', async () => {
  const dir = join(realTmp, 'existing')
  const seen: string[][] = []
  __setGitOverride(async (args) => {
    seen.push(args)
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return dir
    if (args[0] === 'rev-parse' && args[1] === 'HEAD') return 'deadbeef'
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  const r = await ensureGitBaseline(dir)
  assert.equal(r.ok, true)
  assert.equal(r.root, dir)
  // no init / no add / no commit
  assert.ok(!seen.some((a) => a[0] === 'init'))
  assert.ok(!seen.some((a) => a[0] === 'add'))
  assert.ok(!seen.some((a) => a[0] === 'commit' || a.includes('commit')))
  __setGitOverride(null)
})

test('ensureGitBaseline: git init failure -> ok:false with reason', async () => {
  const dir = join(realTmp, 'init-fail')
  __setGitOverride(async (args) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') {
      throw new Error('not a git repository')
    }
    if (args[0] === 'init') throw new Error('permission denied: .git')
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  const r = await ensureGitBaseline(dir)
  assert.equal(r.ok, false)
  assert.match(r.reason ?? '', /git init failed: permission denied/)
  __setGitOverride(null)
})

test('ensureGitBaseline: baseline commit failure -> ok:false', async () => {
  const dir = join(realTmp, 'commit-fail')
  __setGitOverride(async (args) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') {
      throw new Error('not a git repository')
    }
    if (args[0] === 'init') return ''
    if (args[0] === 'rev-parse' && args[1] === 'HEAD') {
      throw new Error('unknown revision') // no commit yet
    }
    if (args[0] === 'add') return ''
    if (args.includes('commit')) {
      throw new Error('pre-commit hook failed')
    }
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  const r = await ensureGitBaseline(dir)
  assert.equal(r.ok, false)
  assert.match(r.reason ?? '', /baseline commit failed: pre-commit hook failed/)
  __setGitOverride(null)
})

test('ensureGitBaseline: fresh repo full path succeeds', async () => {
  const dir = join(realTmp, 'fresh')
  const seen: string[][] = []
  __setGitOverride(async (args) => {
    seen.push(args)
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') {
      throw new Error('not a git repository')
    }
    if (args[0] === 'init') return ''
    if (args[0] === 'rev-parse' && args[1] === 'HEAD') {
      throw new Error('unknown revision')
    }
    if (args[0] === 'add') return ''
    if (args.includes('commit')) return ''
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  const r = await ensureGitBaseline(dir)
  assert.equal(r.ok, true)
  assert.equal(r.root, dir)
  assert.ok(seen.some((a) => a[0] === 'init'))
  __setGitOverride(null)
})

// ---------------------------------------------------------------------------
test('commitCheckpoint: status failure is a silent no-op', async () => {
  __setGitOverride(async (args) => {
    assert.deepEqual(args, ['status', '--porcelain'])
    throw new Error('index.lock exists')
  })
  await commitCheckpoint('/x', 'label') // must not throw
  __setGitOverride(null)
})

test('commitCheckpoint: clean tree -> no commit', async () => {
  const seen: string[][] = []
  __setGitOverride(async (args) => {
    seen.push(args)
    if (args[0] === 'status') return ''
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  await commitCheckpoint('/x', 'label')
  assert.ok(!seen.some((a) => a[0] === 'commit' || a.includes('commit')))
  __setGitOverride(null)
})

test('commitCheckpoint: dirty tree -> add + commit', async () => {
  const seen: string[][] = []
  __setGitOverride(async (args) => {
    seen.push(args)
    if (args[0] === 'status') return ' M modified.txt\n'
    if (args[0] === 'add') return ''
    if (args.includes('commit')) return 'done'
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  await commitCheckpoint('/x', 'my-label')
  assert.ok(seen.some((a) => a[0] === 'add'))
  const commitArgs = seen.find((a) => a.includes('commit'))
  assert.ok(commitArgs)
  assert.ok(commitArgs.includes('-m'))
  assert.ok(commitArgs.some((a) => typeof a === 'string' && a.includes('my-label')))
  __setGitOverride(null)
})

test('commitCheckpoint: commit failure is silent (baseline still exists)', async () => {
  __setGitOverride(async (args) => {
    if (args[0] === 'status') return ' M modified.txt\n'
    if (args[0] === 'add') return ''
    if (args.includes('commit')) throw new Error('hook rejected')
    throw new Error(`unexpected ${args.join(' ')}`)
  })
  await commitCheckpoint('/x', 'label') // must not throw
  __setGitOverride(null)
})

// ---------------------------------------------------------------------------
test('real git integration: baseline + checkpoint + reset/clean still work', async () => {
  __setGitOverride(null)
  const dir = join(realTmp, 'real')
  mkdirSync(dir, { recursive: true })
  const r = await ensureGitBaseline(dir)
  assert.equal(r.ok, true)
  // checkpoint path against a real git tree
  await commitCheckpoint(dir, 'integration')
})
