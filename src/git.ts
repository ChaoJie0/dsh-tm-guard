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

import { execFile } from 'node:child_process'
import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

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
    return root || null
  } catch {
    return null
  }
}

async function hasCommit(root: string): Promise<boolean> {
  try {
    await git(['rev-parse', 'HEAD'], root)
    return true
  } catch {
    return false
  }
}

// Dirs we've already brought to a committed baseline (avoid re-running git).
const ensuredDirs = new Set<string>()

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
  if (ensuredDirs.has(dir)) return { ok: true, root: dir }

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

  ensuredDirs.add(dir)
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
