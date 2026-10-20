/**
 * Git baseline enforcement — the tool-layer rollback safety net.
 *
 * Before a file write is allowed, the gate ensures the target lives inside a
 * git work tree that has at least one committed baseline. If not, it creates
 * one (git init + a .gitignore + a baseline commit). Local git is instant,
 * offline, root-free, and can both revert edits (`git reset --hard`) and
 * remove newly-created files (`git clean -fd`) — unlike Time Machine.
 *
 * All git here runs locally; no remote is ever touched.
 */

import { execFile, execFileSync } from 'node:child_process'
import { existsSync, realpathSync, writeFileSync } from 'node:fs'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

// Test seam: unit tests replace this to inject git outcomes (missing binary,
// failed init/commit, dirty status) without touching the real system.
// Default null = real execution; behaviour is unchanged when not set.
type GitOverride = (args: string[], cwd: string) => Promise<string>
let __gitOverride: GitOverride | null = null
export function __setGitOverride(fn: GitOverride | null): void {
  __gitOverride = fn
}

/** Sensible ignores so an auto-baseline doesn't swallow dependencies/build output. */
const GITIGNORE_LINES = [
  'node_modules/',
  'dist/',
  'build/',
  'out/',
  '.next/',
  'coverage/',
  '.turbo/',
  'target/',
  '__pycache__/',
  '.venv/',
  'venv/',
  '*.log',
  '.env',
  '.env.*',
  '.DS_Store',
  '.tm-guard/',
]

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

async function git(args: string[], cwd: string): Promise<string> {
  if (__gitOverride) {
    return (await __gitOverride(args, cwd)).trim()
  }
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    timeout: 60_000,
    maxBuffer: 1024 * 1024 * 64,
  })
  return stdout.trim()
}

/** Return the git work-tree root containing `dir`, or null if not in a repo. */
export async function repoRoot(dir: string): Promise<string | null> {
  try {
    const root = await git(['rev-parse', '--show-toplevel'], dir)
    return root ? root.trim() : null
  } catch {
    return null
  }
}

/**
 * Read-only probe: can a git baseline be built here, and is git even present?
 *
 * Deliberately does NOT call `ensureGitBaseline`: that runs `git init` plus a
 * baseline commit, and this probe is invoked at plugin load, where mutating the
 * user's workspace would be unacceptable (U-27). "Can it be built?" is answered
 * from `rev-parse` alone.
 *
 * Synchronous, unlike the rest of this module, because its caller (`apply()`)
 * must be able to write the first-run report before returning; see
 * src/baseline-report.ts. One subprocess with a bounded timeout, so blocking
 * plugin load on it is acceptable in a way that blocking on a git *write* would
 * not be.
 *
 * Consults `__gitSyncOverride` so tests can pin the installer-shaped failures
 * (missing binary, not a repository) without touching the real system — the
 * same seam pattern every other git entry point in this module uses.
 */
export function probeGitSync(dir: string): {
  gitAvailable: boolean
  root: string | null
} {
  if (__gitSyncOverride) return __gitSyncOverride(dir)
  try {
    const stdout = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000,
    })
    const root = stdout.trim()
    return { gitAvailable: true, root: root || null }
  } catch (err) {
    // A non-zero exit still proves git ran and answered ("not a repository");
    // ENOENT does not — that is the "git is not installed" case.
    const code = (err as { code?: unknown })?.code
    return { gitAvailable: code !== 'ENOENT', root: null }
  }
}

// Synchronous counterpart of `__gitOverride`, for probeGitSync only. Kept
// separate instead of widening the existing seam: the async override is used by
// fault-injection tests that care about init/commit/status outcomes, and making
// it synchronous would change those call sites.
type GitSyncOverride = (dir: string) => { gitAvailable: boolean; root: string | null }
let __gitSyncOverride: GitSyncOverride | null = null
export function __setGitSyncOverride(fn: GitSyncOverride | null): void {
  __gitSyncOverride = fn
}

export async function hasCommit(root: string): Promise<boolean> {
  try {
    await git(['rev-parse', 'HEAD'], root)
    return true
  } catch {
    return false
  }
}

// Dirs we've already brought to a committed baseline (avoid re-running git).
const ensuredDirs = new Map<string, string>() // dir -> real repo root

export interface BaselineResult {
  ok: boolean
  root?: string
  reason?: string
}

/**
 * Ensure `dir` is a git work tree with at least one committed baseline.
 * Idempotent per directory within a process. Uses an ad-hoc local committer
 * identity so it works without any global git config.
 */
export async function ensureGitBaseline(dir: string): Promise<BaselineResult> {
  const cached = ensuredDirs.get(dir)
  if (cached) return { ok: true, root: cached }

  let root = await repoRoot(dir)
  if (!root) {
    try {
      await git(['init'], dir)
      root = dir
    } catch (err) {
      return { ok: false, reason: `git init failed: ${errMsg(err)}` }
    }
  }

  // Add a .gitignore only if the project doesn't already have one.
  const giPath = join(root, '.gitignore')
  if (!existsSync(giPath)) {
    try {
      writeFileSync(giPath, GITIGNORE_LINES.join('\n') + '\n', 'utf8')
    } catch {
      // best effort
    }
  }

  if (!(await hasCommit(root))) {
    try {
      await git(['add', '-A'], root)
      await git(
        [
          '-c', 'user.name=tm-guard',
          '-c', 'user.email=tm-guard@local',
          'commit',
          '-m', 'tm-guard: baseline checkpoint before autonomous changes',
          '--allow-empty',
        ],
        root,
      )
    } catch (err) {
      return { ok: false, reason: `baseline commit failed: ${errMsg(err)}` }
    }
  }

  ensuredDirs.set(dir, root)
  return { ok: true, root }
}

/**
 * Commit the current working tree state as a checkpoint before a write.
 * This is what makes rollback *precise*: after a checkpoint, a bad write can
 * be reverted to exactly the pre-write state with `git reset --hard`, rather
 * than to an hours-old baseline.
 *
 * No-op when the tree is already clean (avoids empty checkpoint commits).
 * Uses the same ad-hoc committer identity as ensureGitBaseline.
 */
export async function commitCheckpoint(root: string, label: string): Promise<void> {
  // Only commit if there is something to commit (tracked changes, staged,
  // or new files that aren't gitignored).
  let status: string
  try {
    status = await git(['status', '--porcelain'], root)
  } catch {
    return
  }
  if (!status.trim()) return // clean tree — nothing to checkpoint

  try {
    await git(['add', '-A'], root)
    await git(
      [
        '-c', 'user.name=tm-guard',
        '-c', 'user.email=tm-guard@local',
        'commit',
        '-m', `tm-guard: checkpoint before ${label}`,
        '--no-verify',
      ],
      root,
    )
  } catch {
    // Best-effort: if the commit fails (e.g. pre-commit hook, locked index),
    // fall through — the baseline layer still exists, just at an older point.
  }
}
/* ------------------------------------------------------------------ */
/* Ignored-file recovery probe                                         */
/* (docs/proposal-ignored-file-recovery.md, §Performance S1/S3)        */
/* ------------------------------------------------------------------ */

/**
 * Per-target git recoverability as recorded in the audit trail.
 *  - yes     : git can restore the target (tracked, or untracked and
 *              committed by the checkpoint)
 *  - no      : git cannot restore it (matches an ignore rule; `add -A`
 *              never stages it)
 *  - unknown : probe error / git unavailable / checkpoint outcome unproven
 */
export type GitRecoveryState = 'yes' | 'no' | 'unknown'

/** Pre-checkpoint provisional classification (never audited verbatim). */
export type GitRecoveryProbeState = GitRecoveryState | 'untracked'

export interface GitRecoveryProbe {
  /** Absolute, normalized target path. */
  path: string
  /**
   * provisional state before the checkpoint settles:
   *   yes       — tracked (confirmed)
   *   no        — ignored (confirmed)
   *   untracked — neither matched; resolved by the post-checkpoint backfill
   *   unknown   — fatal probe error / target outside every work tree
   */
  state: GitRecoveryProbeState
}

/** Final per-target shape written to AuditRecord.gitRecovery. */
export interface GitRecoveryTarget {
  path: string
  state: GitRecoveryState
}

/** Structured git probe outcome: stdout plus the process exit signal. */
export interface GitProbeResult {
  stdout: string
  /** Process exit code (0/1/128…); undefined for a spawn failure. */
  code?: number
  /** Spawn-level failure code, e.g. 'ENOENT' when git is absent. */
  spawnCode?: string
}

/**
 * Exit-code-aware test seam for the READ-ONLY recovery probes. It reuses the
 * SAME seam convention as `__setGitOverride` but additionally reports the
 * exit code, which the classification depends on (1 = no match vs
 * 128/ENOENT = error). Default null = real execution through `git()`; the
 * probes NEVER spawn their own execFile outside the shared layer.
 */
type GitProbeOverride = (
  args: string[],
  cwd: string,
  stdin: string | null,
) => Promise<GitProbeResult>
let __gitProbeOverride: GitProbeOverride | null = null
export function __setGitProbeOverride(fn: GitProbeOverride | null): void {
  __gitProbeOverride = fn
}

/** Normalize a rejected git() error into an exit/spawn signal. */
function probeErrorSignal(err: unknown): { code?: number; spawnCode?: string } {
  const e = (err ?? {}) as { status?: number; code?: number | string }
  if (typeof e.status === 'number') return { code: e.status }
  if (typeof e.code === 'number') return { code: e.code }
  if (typeof e.code === 'string') {
    if (/^\d+$/.test(e.code)) return { code: Number(e.code) }
    return { spawnCode: e.code } // e.g. ENOENT
  }
  // Seam rejections that only carry a message: treat as a fatal probe error
  // (unknown), never as exit-1 "no match".
  return { code: 128 }
}

/**
 * Run one read-only git probe capturing stdout AND exit code. stdin (when
 * non-null) is piped in — used by `check-ignore --stdin -z` so batch size is
 * bounded by no argv limit.
 *
 * The non-override path shells git directly through execFile (already imported
 * by this module, same binary/timeout/buffer policy as `git()`) because the
 * classification depends on the exit code AND on the partial stdout that a
 * mixed-batch exit 1 still echoes; the string-returning `git()` helper
 * rejects on non-zero and discards that stdout. Tests normally inject
 * __setGitProbeOverride instead, mirroring __setGitOverride; when the string
 * __gitOverride seam is set WITHOUT a probe override (e.g. an existing fault
 * test), probes route through `git()` and map its resolution/ rejection to a
 * code. Never rejects: callers branch on code/spawnCode.
 */
async function gitProbe(args: string[], cwd: string, stdin: string | null): Promise<GitProbeResult> {
  if (__gitProbeOverride) return __gitProbeOverride(args, cwd, stdin)
  if (__gitOverride) {
    // Keep the classic string seam authoritative for tests that set it:
    // resolve → exit 0; reject → fatal (unknown). Exit-1 stdout-set parsing
    // is exercised through the probe override or real git.
    try {
      const stdout = await git(args, cwd)
      return { stdout, code: 0 }
    } catch (err) {
      return { stdout: '', ...probeErrorSignal(err) }
    }
  }
  return new Promise<GitProbeResult>((resolve) => {
    const child = execFile(
      'git',
      args,
      { cwd, timeout: 60_000, maxBuffer: 1024 * 1024 * 64 },
      (err, out) => {
        const stdout = typeof out === 'string' ? out : ''
        if (!err) {
          resolve({ stdout, code: 0 })
          return
        }
        // Partial stdout on a non-zero exit (mixed batch) is preserved here.
        resolve({ stdout, ...probeErrorSignal(err) })
      },
    )
    if (stdin !== null) child.stdin?.end(stdin)
    else child.stdin?.end()
  })
}

function dirnameOf(p: string): string {
  const i = p.lastIndexOf('/')
  return i <= 0 ? '/' : p.slice(0, i)
}

/**
 * Canonicalize a target path against the work-tree toplevel that git reports
 * (already realpath'd by `rev-parse --show-toplevel`). On macOS /tmp and
 * /var are symlinks into /private/…: a caller hands us the LOGICAL path while
 * git's toplevel and echoed paths use the REAL one. Without this remap the
 * tracked-set lookup would never match and every target under a symlinked
 * prefix would be mislabeled. Only the shared prefix is remapped; the
 * remainder of the path (including any not-yet-existing leaf) is preserved.
 * Best-effort: any realpath failure returns the resolved path unchanged.
 */
function canonicalizeForToplevel(absPath: string, toplevel: string): string {
  if (absPath === toplevel || absPath.startsWith(toplevel + sep)) {
    return absPath // already expressed in the toplevel's canonical form
  }
  // Walk the logical path's existing ancestors, realpathing the longest one
  // that exists, then re-append the (possibly non-existent) tail. This keeps
  // deletes of missing files correct: the missing leaf is never stat'ed.
  let dir = dirnameOf(absPath)
  const tail: string[] = [absPath.slice(dir.length + 1)]
  for (;;) {
    try {
      const realDir = realpathSync(dir)
      return join(realDir, ...tail)
    } catch {
      const parent = dirnameOf(dir)
      if (parent === dir) return absPath // filesystem root: give up safely
      tail.unshift(dir.slice(parent.length + 1))
      dir = parent
    }
  }
}

/**
 * Parse the tracked set from `ls-files --error-unmatch -z` stdout.
 *
 * Load-bearing (S1): the batch exits 1 whenever ANY pathspec is untracked
 * while still echoing the matched tracked paths, NUL-separated and repo-
 * relative (even when the input pathspec was absolute). The tracked set is
 * derived ONLY from echoed paths joined back to the toplevel — never from the
 * exit code.
 */
function parseTrackedEcho(stdout: string, toplevel: string): Set<string> {
  const out = new Set<string>()
  for (const part of stdout.split('\0')) {
    if (part) out.add(resolve(toplevel, part))
  }
  return out
}

/**
 * Parse NUL-delimited `check-ignore -v --stdin -z` output.
 *
 * Each ignored target emits FOUR NUL-separated fields
 *   <source>\0<lineno>\0<pattern>\0<path>\0
 * while non-ignored targets emit nothing. Keep only the fourth field (path),
 * which is repo-relative and joined back to the toplevel.
 */
function parseIgnoredEcho(stdout: string, toplevel: string): Set<string> {
  const out = new Set<string>()
  const fields = stdout.split('\0')
  for (let i = 0; i + 3 < fields.length; i += 4) {
    const pathField = fields[i + 3]
    if (pathField) out.add(resolve(toplevel, pathField))
  }
  return out
}

/**
 * Read-only per-target recovery classification, run BEFORE the checkpoint
 * while the targets still exist on disk (hard timing invariant — a probe
 * after removal would see a missing file and be useless).
 *
 * Tracked-first short-circuit (hard invariant): ls-files runs first and each
 * confirmed tracked target is excluded before check-ignore — a file that is
 * both force-added (`git add -f`) and matches an ignore pattern stays
 * recoverable and is never mislabeled ignored.
 *
 * Targets are bucketed by their OWN resolved toplevel (S3): one batched
 * ls-files and one batched check-ignore per toplevel, so a nested repo or
 * submodule is probed with its own cwd/ignore rule set rather than the
 * workspace-root rules.
 *
 * Exit codes: 0 = match; 1 = no match (continue); 128 / ENOENT = probe error
 * → `unknown`, never `no`. Matches come from parsed stdout sets, not exit
 * codes (S1). A probe failure can never deny the write — at worst the target
 * is `unknown`. Relative paths resolve against process.cwd(); results follow
 * de-duplicated input order.
 */
export async function probeGitRecovery(paths: string[]): Promise<GitRecoveryProbe[]> {
  const absPaths: string[] = []
  for (const raw of paths) {
    const abs = isAbsolute(raw) ? resolve(raw) : resolve(process.cwd(), raw)
    if (!absPaths.includes(abs)) absPaths.push(abs)
  }
  if (absPaths.length === 0) return []

  const states = new Map<string, GitRecoveryProbeState>()
  const setIf = (p: string, s: GitRecoveryProbeState): void => {
    if (!states.has(p)) states.set(p, s)
  }

  // One toplevel resolution per distinct parent directory.
  const dirs = [...new Set(absPaths.map(dirnameOf))]
  const topByDir = new Map<string, string | null>()
  await Promise.all(dirs.map(async (d) => {
    topByDir.set(d, await repoRoot(d))
  }))

  // Bucket by toplevel. Keys are CANONICALIZED target paths (a symlinked
  // /tmp or /var prefix is remapped onto git's /private realpath); the result
  // is mapped back to the caller's original (possibly logical) path so audit
  // records show the path the tool actually referenced.
  const canonicalOf = new Map<string, string>() // original -> canonical
  const buckets = new Map<string, string[]>() // toplevel -> canonical targets
  for (const p of absPaths) {
    const top = topByDir.get(dirnameOf(p)) ?? null
    if (!top) {
      setIf(p, 'unknown') // outside every work tree
      continue
    }
    const canonical = canonicalizeForToplevel(p, top)
    canonicalOf.set(p, canonical)
    const list = buckets.get(top)
    if (list) list.push(canonical)
    else buckets.set(top, [canonical])
  }
  const stateByCanonical = new Map<string, GitRecoveryProbeState>()
  const setCanonical = (c: string, s: GitRecoveryProbeState): void => {
    if (!stateByCanonical.has(c)) stateByCanonical.set(c, s)
  }

  for (const [toplevel, targets] of buckets) {
    // --- Stage 1: batched tracked probe (short-circuit) ---------------
    const rel = targets.map((p) => relative(toplevel, p))
    const ls = await gitProbe(
      ['ls-files', '--error-unmatch', '-z', '--', ...rel],
      toplevel,
      null,
    )
    if (ls.code === 0 || ls.code === 1) {
      // 0: all tracked; 1: ≥1 untracked. Either way stdout echoes exactly
      // the tracked members — parse stdout, never the exit code.
      const tracked = parseTrackedEcho(ls.stdout, toplevel)
      const remaining: string[] = []
      for (const c of targets) {
        if (tracked.has(c)) setCanonical(c, 'yes') // never check-ignored
        else remaining.push(c)
      }
      if (remaining.length === 0) continue

      // --- Stage 2: batched ignore probe (bounded stdin/-z) -----------
      const relRemaining = remaining.map((c) => relative(toplevel, c))
      const stdin = relRemaining.join('\0') + '\0'
      const ci = await gitProbe(
        ['check-ignore', '-v', '-z', '--stdin'],
        toplevel,
        stdin,
      )
      if (ci.code === 0) {
        const ignored = parseIgnoredEcho(ci.stdout, toplevel)
        for (const c of remaining) setCanonical(c, ignored.has(c) ? 'no' : 'untracked')
      } else if (ci.code === 1) {
        for (const c of remaining) setCanonical(c, 'untracked') // none ignored
      } else {
        // 128 (fatal) / ENOENT: unknown, never ignored.
        for (const c of remaining) setCanonical(c, 'unknown')
      }
    } else {
      // Fatal tracked probe (128/ENOENT): affected targets unknown; do not
      // run check-ignore on results we could not first prove untracked.
      for (const c of targets) setCanonical(c, 'unknown')
    }
  }

  return absPaths.map((p) => ({
    path: p,
    state: stateByCanonical.get(canonicalOf.get(p) ?? p) ?? states.get(p) ?? 'unknown',
  }))
}

/**
 * Post-checkpoint backfill (S2): re-probe each provisional `untracked`
 * target once with `ls-files --error-unmatch` after commitCheckpoint settles.
 * A hit means the checkpoint's `git add -A` staged and committed it → `yes`;
 * a miss (exit 1) or fatal probe error (128/ENOENT) → `unknown`.
 *
 * commitCheckpoint returns void and swallows add/commit errors, so the caller
 * cannot read a committed flag; this observable re-probe is what distinguishes
 * the two, and a swallowed commit failure is never reported as `yes`.
 * Already-confirmed `yes`/`no`/`unknown` states pass through unchanged.
 */
export async function backfillGitRecovery(
  probes: GitRecoveryProbe[],
): Promise<GitRecoveryTarget[]> {
  const provisional = probes.filter((p) => p.state === 'untracked')
  const committed = new Set<string>()

  const dirs = [...new Set(provisional.map((p) => dirnameOf(p.path)))]
  const topByDir = new Map<string, string | null>()
  await Promise.all(dirs.map(async (d) => {
    topByDir.set(d, await repoRoot(d))
  }))
  // Canonical (symlink-aware) key per provisional target, mirroring the
  // pre-checkpoint probe so echoed tracked paths match under /tmp ↔ /private.
  const canonicalOf = new Map<string, string>() // original path -> canonical
  const buckets = new Map<string, string[]>()
  const unknownCanonical = new Set<string>()
  for (const p of provisional) {
    const top = topByDir.get(dirnameOf(p.path)) ?? null
    if (!top) {
      unknownCanonical.add(p.path)
      continue
    }
    const canonical = canonicalizeForToplevel(p.path, top)
    canonicalOf.set(p.path, canonical)
    const list = buckets.get(top)
    if (list) list.push(canonical)
    else buckets.set(top, [canonical])
  }
  for (const [toplevel, targets] of buckets) {
    const rel = targets.map((c) => relative(toplevel, c))
    const ls = await gitProbe(
      ['ls-files', '--error-unmatch', '-z', '--', ...rel],
      toplevel,
      null,
    )
    if (ls.code === 0 || ls.code === 1) {
      const tracked = parseTrackedEcho(ls.stdout, toplevel)
      for (const c of targets) {
        if (tracked.has(c)) committed.add(c)
        else unknownCanonical.add(c) // checkpoint did not stage/commit it
      }
    } else {
      for (const c of targets) unknownCanonical.add(c) // fatal → unknown
    }
  }

  return probes.map((p) => {
    if (p.state === 'untracked') {
      const key = canonicalOf.get(p.path) ?? p.path
      return { path: p.path, state: committed.has(key) ? 'yes' : 'unknown' }
    }
    return { path: p.path, state: p.state }
  })
}
