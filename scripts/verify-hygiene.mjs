#!/usr/bin/env node
/**
 * Git hygiene gate — `npm run verify:hygiene` (L6-a tree + L6-b history)
 *
 * Machine version of the manual privacy sweeps in RELEASE.md §1 L6-a/L6-b.
 * Pure Node, read-only git plumbing via execFileSync (no shell, no network).
 *
 * Scope model (why not a blind `rev-list --all`):
 *   - HARD FAIL range = what will actually be pushed: the published baseline
 *     `origin/main` plus the new commits `origin/main..HEAD`. A leak here reaches
 *     the public remote and blocks release.
 *   - WARN-only range = orphan local history (backup branches, dangling
 *     checkpoints) that is NOT on the push lineage. It never leaves the machine
 *     on `git push origin main`, so it is listed for cleanup but does not fail.
 *
 * L6-a: clean porcelain (commit/stash first, same precondition as L1), no
 *        tracked review/research/scratch artifacts, no real local username /
 *        session id / secret in HEAD blobs.
 * L6-b: push-lineage history carries no forbidden path or sensitive string;
 *        new-commit author metadata is reported (legacy local identities are
 *        accepted by decision, so this is a warning, not a failure).
 *
 * Exit code: 0 = clean; 1 = any hard violation.
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

// git grep uses ERE (no JS lookahead) and accepts a single ref, not a range.
// No-match exits 1; any other status (e.g. 128 fatal) must surface as a bug.
function git(args) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
  } catch (e) {
    if (e.status === 1 && !(e.stderr || '').includes('fatal')) return ''
    throw e
  }
}

if (!existsSync(join(ROOT, '.git'))) {
  console.error('✗ not a git checkout — hygiene check requires git')
  process.exit(1)
}

// --- Allowed neutral placeholders for /Users/<name> (RELEASE L6-a note) ---
const ALLOWED_USER_SEGMENTS = ['alice', 'you', 'me', 'x', 'demo', 'user', 'home', 'guest']
const REAL_USERS = ['zero', 'root', 'admin']

// Real local absolute path under a real account (zero/root/admin), not neutral placeholders.
const REAL_PATH_RE = new RegExp(`/Users/(${REAL_USERS.join('|')})(?![A-Za-z0-9_-])`)
const SESSION_RE = /session-[0-9a-f]{8,}/
const SECRET_RES = [
  /ghp_[A-Za-z0-9]{20,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /sk-[A-Za-z0-9_-]{16,}/,
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
]
// ERE variants for single-ref `git grep` (no lookahead, no alternation issue).
const GIT_REAL_PATH = `/Users/(${REAL_USERS.join('|')})([^A-Za-z0-9_-]|$)`
const GIT_SESSION = 'session-[0-9a-f]{8,}'
const GIT_SECRETS = [
  'ghp_[A-Za-z0-9]{20,}',
  'github_pat_[A-Za-z0-9_]{20,}',
  'sk-[A-Za-z0-9_-]{16,}',
  'AKIA[0-9A-Z]{16}',
  '-----BEGIN [A-Z ]*PRIVATE KEY-----',
]

// Tracked paths that must never be committed (anchored, not loose substrings).
const FORBIDDEN_DIR_SEGMENTS = new Set(['docs', 'research-proposal', '.smoke-out'])
const FORBIDDEN_BASENAME = [
  /^scratch-.*\.mts$/,
  /\.log$/,
  /(^|[-_])(fp-review|final-release|audit-gap|independent-review)([-_.]|$)/i,
]
// Legit test files may carry the `fp` (false-positive) token; exempt from the
// review-word basename rule, still scanned for real paths/secrets.
const TEST_FILE_RE = /^test-.*\.(mts|mjs)$/

const failures = []
const warnings = []
function fail(msg) { failures.push(msg) }
function warn(msg) { warnings.push(msg) }

// ---------------------------------------------------------------------------
// L6-a (1): porcelain must be empty — commit/stash before release (L1 precondition)
// ---------------------------------------------------------------------------
const porcelain = git(['status', '--porcelain=v1', '--untracked-files=normal']).trim()
if (porcelain) {
  const lines = porcelain.split('\n').filter(Boolean)
  fail(`working tree not clean (${lines.length} change(s)); commit or stash first — L1/L6 require HEAD`)
  for (const l of lines.slice(0, 12)) console.log(`  dirty  ${l}`)
} else {
  console.log('L6-a porcelain: clean ✅')
}

// ---------------------------------------------------------------------------
// L6-a (2): tracked-path hygiene (anchored, test allowlist)
// ---------------------------------------------------------------------------
const tracked = git(['ls-files']).split('\n').filter(Boolean)
for (const path of tracked) {
  const segs = path.split('/')
  const base = segs[segs.length - 1]
  if (FORBIDDEN_DIR_SEGMENTS.has(segs[0])) {
    fail(`tracked forbidden directory: ${path}`)
    continue
  }
  if (TEST_FILE_RE.test(base)) continue
  if (FORBIDDEN_BASENAME.some((re) => re.test(base))) {
    fail(`tracked review/scratch artifact: ${path}`)
  }
}
if (!failures.some((f) => f.startsWith('tracked'))) {
  console.log('L6-a tracked paths: no review/research/scratch artifacts ✅')
}

// ---------------------------------------------------------------------------
// L6-a (3): HEAD blobs — real local path / session id / secret (single ref)
// ---------------------------------------------------------------------------
function grepRef(ref, ere) {
  // `-e` keeps patterns that start with `-` (PEM headers) from being parsed as flags;
  // `-a` treats binary blobs as text so ASCII secrets inside a binary are still scanned.
  return git(['grep', '-na', '-E', '-e', ere, ref, '--'])
    .split('\n').filter(Boolean).map((l) => `${ref}: ${l}`)
}

const headHits = [
  ...grepRef('HEAD', GIT_REAL_PATH),
  ...grepRef('HEAD', GIT_SESSION),
  ...GIT_SECRETS.flatMap((e) => grepRef('HEAD', e)),
]
for (const hit of headHits) fail(`HEAD blob: ${hit}`)
if (!failures.some((f) => f.startsWith('HEAD blob'))) {
  console.log('L6-a HEAD blobs: no real path / session id / secret ✅')
}

// ---------------------------------------------------------------------------
// L6-b (1): push-lineage history = origin/main baseline + new commits
// ---------------------------------------------------------------------------
let newCommits = []
let baselineAvailable = true
try {
  git(['rev-parse', '--verify', 'origin/main'])
} catch {
  baselineAvailable = false
  warn('origin/main ref unavailable (shallow clone / first push); baseline + new-commit history scan skipped — run on a full clone for L6-b')
}

if (baselineAvailable) {
  try {
    newCommits = git(['rev-list', 'origin/main..HEAD']).split('\n').filter(Boolean)
  } catch {
    warn('origin/main..HEAD not resolvable; skipped new-commit range')
  }

  // Baseline published tree must also be clean of sensitive strings.
  for (const ere of [GIT_REAL_PATH, GIT_SESSION, ...GIT_SECRETS]) {
    for (const hit of grepRef('origin/main', ere)) fail(`origin/main blob: ${hit}`)
  }
}

// Forbidden paths that appear in the new-commit range (would be pushed).
if (newCommits.length) {
  const names = git(['log', 'origin/main..HEAD', '--name-only', '--pretty=format:'])
    .split('\n').map((s) => s.trim()).filter(Boolean)
  for (const path of names) {
    const segs = path.split('/')
    const base = segs[segs.length - 1]
    if (FORBIDDEN_DIR_SEGMENTS.has(segs[0]) || FORBIDDEN_BASENAME.some((re) => re.test(base))) {
      fail(`new commit introduces forbidden path: ${path}`)
    }
  }
  // Sensitive strings in new-commit diffs (git grep cannot take a range; scan -p).
  const patch = git(['log', 'origin/main..HEAD', '-p', '--no-color'])
  for (const re of [REAL_PATH_RE, SESSION_RE, ...SECRET_RES]) {
    for (const line of patch.split('\n')) {
      if (line.startsWith('+') && re.test(line)) fail(`new history: ${line.trim().slice(0, 160)}`)
    }
  }
}
console.log(`L6-b push lineage: ${newCommits.length} new commit(s) scanned ✅`)

// ---------------------------------------------------------------------------
// L6-b (2): new-commit author metadata — WARN only (legacy local identity accepted)
// ---------------------------------------------------------------------------
if (newCommits.length) {
  const meta = git(['log', 'origin/main..HEAD', '--format=%an|%ae|%cn|%ce'])
  const localMeta = [...new Set(meta.split('\n').filter(Boolean))].filter((line) =>
    /zero@|S3-MacBook|tm-guard@local|\.local/i.test(line))
  for (const m of localMeta) warn(`new-commit local author identity (accepted, non-blocking): ${m}`)
}

// ---------------------------------------------------------------------------
// L6-b (3): orphan local history (backup branches / dangling) — WARN only
// ---------------------------------------------------------------------------
let orphans = []
try {
  orphans = git(['rev-list', '--all', '--not', 'origin/main', 'HEAD']).split('\n').filter(Boolean)
} catch { /* no orphan set */ }
if (orphans.length) {
  const names = git(['log', ...orphans.slice(0, 200), '--name-only', '--pretty=format:'])
    .split('\n').map((s) => s.trim()).filter(Boolean)
  const orphanHits = [...new Set(names)].filter((path) => {
    const segs = path.split('/')
    const base = segs[segs.length - 1]
    return FORBIDDEN_DIR_SEGMENTS.has(segs[0]) || FORBIDDEN_BASENAME.some((re) => re.test(base))
  })
  if (orphanHits.length) {
    warn(`${orphans.length} orphan local commit(s) hold review/research files NOT on the push lineage; clean up backup branches/dangling refs before they are pushed elsewhere:`)
    for (const h of orphanHits.slice(0, 10)) warn(`  orphan  ${h}`)
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
console.log('')
for (const w of warnings) console.log(`⚠  ${w}`)
if (failures.length) {
  console.error('')
  console.error('✗ Hygiene violations:')
  for (const f of failures) console.error(`  - ${f}`)
  process.exit(1)
}
console.log(`PASS: L6-a tree + L6-b push-lineage history clean (${warnings.length} warning(s) non-blocking)`)
process.exit(0)
