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
import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
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
