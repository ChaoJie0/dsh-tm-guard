// U-26 — tm_git_bloat: read-only .git size diagnosis.
//
// Two layers are covered:
//   1. Real-repo behaviour: build a throwaway repository whose SECOND commit
//      adds a large file, and assert the scan surfaces that blob (and the
//      commit that introduced it) rather than any small file.
//   2. The safety contract: the tool never mutates the repository, and a
//      non-repository target returns guidance text instead of throwing.
//
// The read-only guarantee is asserted structurally (git invocations captured
// through the seam contain no destructive subcommand) as well as behaviourally
// (HEAD, the ref log and the work tree are unchanged after a scan).
import { test, after, before } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  analyzeGitBloat,
  diagnoseGitBloat,
  formatBytes,
  formatBloatReport,
  parseBatchCheck,
  NotARepoError,
  __setBloatGitOverride,
} from './src/bloat.ts'
import { __setGitOverride } from './src/git.ts'

let DIR = '' // repo with a big blob in commit #2
let PLAIN = '' // directory that is not a git repo
const BIG_BYTES = 512 * 1024

function git(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' })
}

before(() => {
  DIR = mkdtempSync(join(tmpdir(), 'tm-bloat-'))
  git(['init', '-q'], DIR)
  git(['config', 'user.email', 't@t'], DIR)
  git(['config', 'user.name', 't'], DIR)
  git(['config', 'commit.gpgsign', 'false'], DIR)

  // Commit 1: only small files — the baseline.
  writeFileSync(join(DIR, 'small.txt'), 'tiny\n')
  writeFileSync(join(DIR, 'README.md'), '# demo\n')
  git(['add', '-A'], DIR)
  git(['commit', '-qm', 'first: small files only'], DIR)

  // Commit 2: introduce one large, incompressible blob.
  writeFileSync(join(DIR, 'huge-dataset.bin'), Buffer.alloc(BIG_BYTES, 0xab))
  git(['add', '-A'], DIR)
  git(['commit', '-qm', 'second: add the huge dataset'], DIR)

  PLAIN = mkdtempSync(join(tmpdir(), 'tm-bloat-plain-'))
})

after(() => {
  __setBloatGitOverride(null)
  __setGitOverride(null)
  rmSync(DIR, { recursive: true, force: true })
  rmSync(PLAIN, { recursive: true, force: true })
})

test('tm_git_bloat: ranks the large blob from commit #2 in the top list', async () => {
  const report = await analyzeGitBloat(DIR)
  assert.equal(report.entries.length > 0, true, 'expected at least one ranked blob')

  const top = report.entries[0]
  assert.equal(top.rank, 1)
  assert.equal(top.path, 'huge-dataset.bin', `largest blob should be the big file, got ${top.path}`)
  assert.equal(top.size, BIG_BYTES, 'size should match the bytes written')
  assert.ok(top.size > 1024 * 100, 'sanity: the detected blob really is large')

  // Small files from commit #1 must not outrank it.
  const paths = report.entries.map((e) => e.path)
  assert.equal(paths.includes('small.txt') && report.entries.find((e) => e.path === 'small.txt')!.rank < top.rank, false)
})

test('tm_git_bloat: attributes the introducing commit (hash + message)', async () => {
  const report = await analyzeGitBloat(DIR)
  const top = report.entries.find((e) => e.path === 'huge-dataset.bin')!
  assert.ok(top.commit, 'the big blob should be attributed to a commit')

  const expected = git(['log', '--format=%H', '-1'], DIR).trim()
  assert.equal(top.commit!.hash, expected, 'introducing commit should be the one that added the file')
  assert.match(top.commit!.subject, /huge dataset/, `subject was ${top.commit!.subject}`)
})

test('tm_git_bloat: total blob accounting counts the large blob once', async () => {
  const report = await analyzeGitBloat(DIR)
  assert.ok(report.totalBlobBytes >= BIG_BYTES, `total ${report.totalBlobBytes} should exceed the big blob`)
  assert.ok(report.totalBlobs >= 3, `expected >= 3 blobs, got ${report.totalBlobs}`)
  // Deduplication: no oid appears twice in the ranked list.
  const oids = report.entries.map((e) => e.oid)
  assert.equal(new Set(oids).size, oids.length, 'ranked blobs must be unique by oid')
})

test('tm_git_bloat: topN bounds the report and is sorted descending', async () => {
  const report = await analyzeGitBloat(DIR, { topN: 2 })
  assert.equal(report.entries.length, 2)
  assert.ok(report.entries[0].size >= report.entries[1].size, 'entries must be size-descending')
})

test('tm_git_bloat: is READ-ONLY — refs, HEAD and work tree unchanged', async () => {
  const before = {
    head: git(['rev-parse', 'HEAD'], DIR).trim(),
    refs: git(['show-ref'], DIR).trim(),
    files: readdirSync(DIR).sort().join(','),
  }

  const seen: string[][] = []
  __setBloatGitOverride(async (args) => {
    seen.push(args)
    return execFileSync('git', args, { cwd: DIR, encoding: 'utf8', maxBuffer: 1 << 28 })
  })
  try {
    await analyzeGitBloat(DIR, { topN: 3 })
  } finally {
    __setBloatGitOverride(null)
  }

  // Structural guarantee: only query subcommands were ever invoked.
  const FORBIDDEN = /\b(rm|mv|gc|prune|repack|filter-repo|filter-branch|bfg|reset|checkout|clean|reflog|update-ref|stash|commit|push)\b/
  for (const args of seen) {
    const joined = args.join(' ')
    assert.equal(FORBIDDEN.test(joined), false, `read-only violation: git ${joined}`)
  }
  assert.ok(seen.length > 0, 'the scan should have invoked git at least once')
  assert.ok(seen.some((a) => a[0] === 'rev-list'), 'scan should use rev-list --objects --all')
  assert.ok(
    seen.some((a) => a[0] === 'cat-file'),
    'scan should read object metadata through cat-file',
  )

  assert.equal(git(['rev-parse', 'HEAD'], DIR).trim(), before.head, 'HEAD moved — not read-only')
  assert.equal(git(['show-ref'], DIR).trim(), before.refs, 'refs changed — not read-only')
  assert.equal(readdirSync(DIR).sort().join(','), before.files, 'work tree changed — not read-only')
  assert.equal(readFileSync(join(DIR, 'huge-dataset.bin')).length, BIG_BYTES, 'the big file was modified')
})

test('tm_git_bloat: no git repository -> guidance text, never throws', async () => {
  await assert.rejects(
    () => analyzeGitBloat(PLAIN),
    (err: unknown) => err instanceof NotARepoError,
    'analyzeGitBloat should signal a typed NotARepoError',
  )

  // The tool-facing entry point must degrade to text.
  const text = await diagnoseGitBloat(PLAIN)
  assert.match(text, /not a git repository/i)
  assert.match(text, /read-only/i)
  assert.doesNotMatch(text, /at .*bloat\.ts:\d+/, 'should not leak a stack trace')
})

test('tm_git_bloat: git failure -> readable message, never throws', async () => {
  __setBloatGitOverride(async () => { throw new Error('git: command not found') })
  try {
    const text = await diagnoseGitBloat(DIR)
    assert.match(text, /Diagnosis failed/)
    assert.match(text, /command not found/)
    assert.match(text, /read-only/i, 'failure text should restate the read-only guarantee')
  } finally {
    __setBloatGitOverride(null)
  }
})

test('tm_git_bloat: empty repository (no commits) is handled', async () => {
  const empty = mkdtempSync(join(tmpdir(), 'tm-bloat-empty-'))
  try {
    git(['init', '-q'], empty)
    const report = await analyzeGitBloat(empty)
    assert.equal(report.entries.length, 0)
    assert.equal(report.totalBlobBytes, 0)
    const text = await diagnoseGitBloat(empty)
    assert.match(text, /No reachable blob objects/)
  } finally {
    rmSync(empty, { recursive: true, force: true })
  }
})

test('tm_git_bloat: rendered table shows rank/path/size/commit and the manual-cleanup caveat', async () => {
  const text = await diagnoseGitBloat(DIR, { topN: 5 })
  assert.match(text, /read-only/i)
  assert.match(text, /huge-dataset\.bin/)
  assert.match(text, /Introduced by/)
  assert.match(text, /huge dataset/, 'the introducing commit subject should be rendered')
  // The tool must tell the agent that cleanup is manual and destructive.
  assert.match(text, /manual|manually/i)
  assert.match(text, /filter-repo|BFG/)
  assert.match(text, /no history was modified/i)
})

test('formatBytes: human-readable sizes', () => {
  assert.equal(formatBytes(0), '0 B')
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(1024), '1.0 KB')
  assert.equal(formatBytes(1536), '1.5 KB')
  assert.equal(formatBytes(1024 * 1024), '1.0 MB')
  assert.equal(formatBytes(20 * 1024 * 1024), '20 MB')
  assert.equal(formatBytes(-1), '?')
})

test('parseBatchCheck: keeps blobs, ignores trees/commits and malformed lines', () => {
  const parsed = parseBatchCheck(
    [
      'blob aaaa1111 100 big.bin',
      'tree bbbb2222 40',            // no path, wrong type -> skipped (type)
      'commit cccc3333 300',         // skipped (type)
      'blob dddd4444 2048 with space in name.bin',
      '',
      'total garbage',
      'blob eeee5555',               // missing size -> skipped
    ].join('\n'),
  )
  assert.deepEqual(parsed, [
    { oid: 'aaaa1111', size: 100, path: 'big.bin' },
    { oid: 'dddd4444', size: 2048, path: 'with space in name.bin' },
  ])
})

test('formatBloatReport: empty report renders an explicit nothing-to-do line', () => {
  const text = formatBloatReport({ root: '/x', totalBlobBytes: 0, totalBlobs: 0, entries: [] })
  assert.match(text, /No reachable blob objects/)
  assert.match(text, /read-only/i)
})
