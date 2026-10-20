// Unit tests for the ignored-file recovery probe (src/git.ts).
//
// Covers proposal docs/proposal-ignored-file-recovery.md §Performance/Tests:
// tracked-first short-circuit, batched stdout-set parsing (S1), per-toplevel
// bucketing (S3), exit 1 vs 128/ENOENT separation, post-checkpoint backfill
// (S2), non-existent paths, and real-git end-to-end classification.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, realpathSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  __setGitOverride,
  __setGitProbeOverride,
  probeGitRecovery,
  backfillGitRecovery,
  commitCheckpoint,
} from './src/git.ts'

const NUL = String.fromCharCode(0)
const TOP = '/private/tmp/ifr-unit-repo'

after(() => {
  __setGitOverride(null)
  __setGitProbeOverride(null)
})

/** Wire repoRoot() (git() seam) + the probe seam to a fixed fake toplevel. */
function fakeToplevel(top = TOP): void {
  __setGitOverride(async (args: string[]) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return top
    return ''
  })
}

/** check-ignore 4-field NUL record for one ignored relative path. */
function ignoreRecord(pattern: string, rel: string): string {
  return ['.gitignore', '1', pattern, rel, ''].join(NUL)
}

test('recovery: tracked target -> yes and check-ignore never runs', async () => {
  fakeToplevel()
  let checkIgnoreCalled = false
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: 'tracked.txt' + NUL, code: 0 }
    if (args[0] === 'check-ignore') {
      checkIgnoreCalled = true
      return { stdout: '', code: 1 }
    }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery([join(TOP, 'tracked.txt')])
  assert.deepEqual(r, [{ path: join(TOP, 'tracked.txt'), state: 'yes' }])
  assert.equal(checkIgnoreCalled, false, 'tracked-first short-circuit must skip check-ignore')
})

test('recovery: ignored target -> no', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') {
      return { stdout: ignoreRecord('.env.*', '.env.local'), code: 0 }
    }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery([join(TOP, '.env.local')])
  assert.equal(r[0].state, 'no')
})

test('recovery: untracked non-ignored target -> provisional untracked', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') return { stdout: '', code: 1 }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery([join(TOP, 'new.txt')])
  assert.equal(r[0].state, 'untracked')
})

test('recovery: mixed batch tracked+ignored+untracked parsed from stdout sets (S1)', async () => {
  fakeToplevel()
  let lsStdin: string | null = null
  __setGitProbeOverride(async (args: string[], _cwd: string, stdin: string | null) => {
    if (args[0] === 'ls-files') {
      // Batch exits 1 (new.txt untracked) yet stdout echoes tracked.txt.
      return { stdout: 'tracked.txt' + NUL, code: 1 }
    }
    if (args[0] === 'check-ignore') {
      lsStdin = stdin
      // Only .env.local is in the remaining set and is ignored.
      return { stdout: ignoreRecord('.env.*', '.env.local'), code: 0 }
    }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery(
    ['tracked.txt', '.env.local', 'new.txt'].map((f) => join(TOP, f)),
  )
  assert.deepEqual(r.map((p) => p.state), ['yes', 'no', 'untracked'])
  // remaining set excludes the tracked short-circuit member
  assert.ok(lsStdin?.includes('.env.local'))
  assert.ok(!lsStdin?.includes('tracked.txt'))
})

test('recovery: check-ignore exit 1 (not ignored) vs 128 (fatal) are not conflated', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') return { stdout: '', code: 1 }
    return { stdout: '', code: 1 }
  })
  assert.equal((await probeGitRecovery([join(TOP, 'a.txt')]))[0].state, 'untracked')

  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') return { stdout: '', code: 128 }
    return { stdout: '', code: 1 }
  })
  assert.equal((await probeGitRecovery([join(TOP, 'b.txt')]))[0].state, 'unknown')
})

test('recovery: ls-files fatal 128 -> unknown and check-ignore never runs', async () => {
  fakeToplevel()
  let ci = false
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 128 }
    if (args[0] === 'check-ignore') { ci = true; return { stdout: '', code: 1 } }
    return { stdout: '', code: 1 }
  })
  assert.equal((await probeGitRecovery([join(TOP, 'c.txt')]))[0].state, 'unknown')
  assert.equal(ci, false)
})

test('recovery: git unavailable (ENOENT) -> unknown, never no', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', spawnCode: 'ENOENT' }
    return { stdout: '', spawnCode: 'ENOENT' }
  })
  assert.equal((await probeGitRecovery([join(TOP, 'd.txt')]))[0].state, 'unknown')
})

test('recovery: non-existent path classified by name; no crash', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 1 }
    if (args[0] === 'check-ignore') return { stdout: ignoreRecord('*.ghost', 'does-not-exist.ghost'), code: 0 }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery([join(TOP, 'does-not-exist.ghost')])
  assert.equal(r[0].state, 'no') // name matches an ignore rule even with the file absent
})

test('recovery: target outside every work tree -> unknown', async () => {
  // repoRoot seam reports null regardless of dir
  __setGitOverride(async () => '')
  __setGitProbeOverride(async () => ({ stdout: '', code: 0 }))
  const r = await probeGitRecovery(['/no/repo/here/file.txt'])
  assert.equal(r[0].state, 'unknown')
})

test('recovery: relative paths resolve against process.cwd()', async () => {
  fakeToplevel(TOP)
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: 'rel.txt' + NUL, code: 0 }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery(['rel.txt'])
  assert.equal(r[0].path, join(process.cwd(), 'rel.txt'))
})

test('recovery: backfill hit -> yes; miss (swallowed commit fail) -> unknown (S2)', async () => {
  fakeToplevel()
  const provisional = [
    { path: join(TOP, 'committed.txt'), state: 'untracked' as const },
    { path: join(TOP, 'lost.txt'), state: 'untracked' as const },
  ]
  // Backfill batch: committed.txt now tracked, lost.txt still missing (exit 1
  // + partial stdout) — exactly what a swallowed commit failure looks like.
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: 'committed.txt' + NUL, code: 1 }
    return { stdout: '', code: 1 }
  })
  const out = await backfillGitRecovery(provisional)
  assert.deepEqual(out.map((t) => [t.path.split('/').pop(), t.state]), [
    ['committed.txt', 'yes'],
    ['lost.txt', 'unknown'],
  ])
})

test('recovery: backfill leaves confirmed yes/no/unknown untouched', async () => {
  fakeToplevel()
  __setGitProbeOverride(async () => ({ stdout: '', code: 128 }))
  const out = await backfillGitRecovery([
    { path: join(TOP, 't.txt'), state: 'yes' },
    { path: join(TOP, 'i.log'), state: 'no' },
    { path: join(TOP, 'u.txt'), state: 'unknown' },
  ])
  assert.deepEqual(out.map((t) => t.state), ['yes', 'no', 'unknown'])
})

test('recovery: backfill fatal 128 on provisional target -> unknown, never yes', async () => {
  fakeToplevel()
  __setGitProbeOverride(async (args: string[]) => {
    if (args[0] === 'ls-files') return { stdout: '', code: 128 }
    return { stdout: '', code: 128 }
  })
  const out = await backfillGitRecovery([{ path: join(TOP, 'u.txt'), state: 'untracked' }])
  assert.equal(out[0].state, 'unknown')
})

test('recovery: two toplevels bucketed separately, inner ignore rules win (S3)', async () => {
  const OUTER = '/private/tmp/ifr-outer'
  const INNER = join(OUTER, 'inner')
  __setGitOverride(async (args: string[], cwd: string) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') {
      return cwd.startsWith(INNER) ? INNER : OUTER
    }
    return ''
  })
  const seenCwd: string[] = []
  __setGitProbeOverride(async (args: string[], cwd: string) => {
    seenCwd.push(cwd)
    if (args[0] === 'ls-files') {
      // outer file tracked; inner file untracked
      if (cwd === OUTER) return { stdout: 'outer-tracked.txt' + NUL, code: 0 }
      return { stdout: '', code: 1 }
    }
    if (args[0] === 'check-ignore') {
      // only the INNER cwd ever runs check-ignore; inner marks inner-only.log
      assert.equal(cwd, INNER)
      return { stdout: ignoreRecord('*.log', 'inner-only.log'), code: 0 }
    }
    return { stdout: '', code: 1 }
  })
  const r = await probeGitRecovery([
    join(OUTER, 'outer-tracked.txt'),
    join(INNER, 'inner-only.log'),
  ])
  assert.deepEqual(r.map((p) => p.state), ['yes', 'no'])
  assert.ok(seenCwd.includes(OUTER) && seenCwd.includes(INNER))
})

test('recovery: real git — full lifecycle tracked/ignored/force-added/untracked', async () => {
  __setGitOverride(null)
  __setGitProbeOverride(null)
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'ifr-real-')))
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir })
    execFileSync('git', ['config', 'user.email', 't@t'], { cwd: dir })
    execFileSync('git', ['config', 'user.name', 't'], { cwd: dir })
    writeFileSync(join(dir, '.gitignore'), '.env.*\n')
    writeFileSync(join(dir, 'tracked.txt'), 't')
    writeFileSync(join(dir, '.env.local'), 'secret')
    writeFileSync(join(dir, 'forced.env'), 'force')
    execFileSync('git', ['add', 'tracked.txt'], { cwd: dir })
    execFileSync('git', ['add', '-f', 'forced.env'], { cwd: dir })
    execFileSync('git', ['commit', '-qm', 'base'], { cwd: dir })
    writeFileSync(join(dir, 'new.txt'), 'brand-new')

    const pre = await probeGitRecovery(
      ['tracked.txt', '.env.local', 'forced.env', 'new.txt', 'ghost.txt'].map((f) => join(dir, f)),
    )
    assert.deepEqual(pre.map((p) => p.state), ['yes', 'no', 'yes', 'untracked', 'untracked'])

    await commitCheckpoint(dir, 'recovery-real')
    const post = await backfillGitRecovery(pre)
    // new.txt was committed -> yes; absent ghost.txt never staged -> unknown
    assert.deepEqual(post.map((p) => [p.path.split('/').pop(), p.state]), [
      ['tracked.txt', 'yes'],
      ['.env.local', 'no'],
      ['forced.env', 'yes'],
      ['new.txt', 'yes'],
      ['ghost.txt', 'unknown'],
    ])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('recovery: real git — nested repo uses its own ignore rules', async () => {
  __setGitOverride(null)
  __setGitProbeOverride(null)
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'ifr-nest-')))
  try {
    const inner = join(root, 'inner')
    mkdirSync(inner, { recursive: true })
    for (const cwd of [root, inner]) {
      execFileSync('git', ['init', '-q'], { cwd })
      execFileSync('git', ['config', 'user.email', 't@t'], { cwd })
      execFileSync('git', ['config', 'user.name', 't'], { cwd })
    }
    writeFileSync(join(root, '.gitignore'), 'shared-secret.log\n')
    writeFileSync(join(root, 'shared-secret.log'), 'outer')
    // inner repo deliberately does NOT ignore shared-secret.log
    writeFileSync(join(inner, '.gitignore'), 'inner-only.log\n')
    writeFileSync(join(inner, 'shared-secret.log'), 'inner-recoverable')
    writeFileSync(join(inner, 'inner-only.log'), 'x')
    execFileSync('git', ['add', '-A'], { cwd: inner })
    execFileSync('git', ['commit', '-qm', 'inner'], { cwd: inner })
    execFileSync('git', ['add', '-A'], { cwd: root })
    execFileSync('git', ['commit', '-qm', 'outer'], { cwd: root })

    const r = await probeGitRecovery([
      join(root, 'shared-secret.log'),
      join(inner, 'shared-secret.log'),
      join(inner, 'inner-only.log'),
    ])
    assert.deepEqual(r.map((p) => p.state), ['no', 'yes', 'no'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('recovery: user .gitignore is never modified by a probe', async () => {
  __setGitOverride(null)
  __setGitProbeOverride(null)
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'ifr-gi-')))
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir })
    execFileSync('git', ['config', 'user.email', 't@t'], { cwd: dir })
    execFileSync('git', ['config', 'user.name', 't'], { cwd: dir })
    const gi = join(dir, '.gitignore')
    writeFileSync(gi, 'keep-me-*.log\n')
    writeFileSync(join(dir, 'keep-me-x.log'), 'x')
    execFileSync('git', ['add', '-A'], { cwd: dir })
    execFileSync('git', ['commit', '-qm', 'base'], { cwd: dir })
    const before = readFileSync(gi)
    await probeGitRecovery([join(dir, 'keep-me-x.log')])
    const after = readFileSync(gi)
    assert.ok(before.equals(after), '.gitignore bytes must be unchanged')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
