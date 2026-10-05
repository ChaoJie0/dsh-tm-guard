/**
 * Read-only `.git` bloat diagnosis — what is making this repository fat.
 *
 * A repo that has been running for a while accumulates large blobs (datasets,
 * tarballs, build output committed by mistake). Those blobs stay reachable in
 * history forever, so deleting the file in a later commit frees nothing: the
 * pack still carries it, and every clone/fetch pays for it.
 *
 * This module answers the three questions needed to act on that:
 *   1. Which blobs are the biggest?   (rev-list --objects --all | cat-file)
 *   2. Where do they live?            (the path recorded next to the blob)
 *   3. Which commit introduced them?  (git log --diff-filter=A --find-object)
 *
 * HARD CONSTRAINT — READ ONLY. Every git invocation below is a pure query
 * (`rev-list`, `cat-file --batch-check`, `log`, `count-objects`). Nothing here
 * runs `rm`, `mv`, `gc`, `prune`, `filter-repo` or BFG, and nothing rewrites
 * history. Actually shrinking the repo is a destructive, history-rewriting
 * operation that must be a deliberate human decision (it invalidates every
 * existing clone and commit hash) — see the "read-only diagnosis" note in the
 * tm_git_bloat tool description and the README.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { repoRoot } from './git.ts'

const execFileAsync = promisify(execFile)

/** How many blobs the report ranks. */
export const BLOAT_TOP_N = 20

/** Large repos can emit a lot of lines; cap the buffer generously. */
const MAX_BUFFER = 1024 * 1024 * 256
const GIT_TIMEOUT_MS = 120_000

/** One ranked entry in the bloat report. */
export interface BloatEntry {
  /** 1-based rank in the size-ordered list. */
  rank: number
  /** Object id (sha1/sha256) of the blob. */
  oid: string
  /** Path this blob was seen at, as recorded in the commit that referenced it. */
  path: string
  /** Uncompressed blob size in bytes. */
  size: number
  /** Commit that introduced this blob (empty when it could not be attributed). */
  commit?: {
    hash: string
    /** First line of the commit subject. */
    subject: string
    /** Author date, ISO-8601. */
    date: string
  }
}

export interface BloatReport {
  /** Repository root the analysis ran against. */
  root: string
  /** Total bytes of all reachable blobs. */
  totalBlobBytes: number
  /** Number of reachable blobs. */
  totalBlobs: number
  /** Largest blobs, descending by size. */
  entries: BloatEntry[]
}

/**
 * Test seam, mirroring git.ts's `__setGitOverride`. When set, all git calls in
 * this module are routed through it so failure branches (missing binary, not a
 * repo, unreadable pack) can be exercised without a real repository.
 */
type BloatGitOverride = (args: string[], cwd: string) => Promise<string>
let __bloatGitOverride: BloatGitOverride | null = null
export function __setBloatGitOverride(fn: BloatGitOverride | null): void {
  __bloatGitOverride = fn
}

async function git(args: string[], cwd: string): Promise<string> {
  if (__bloatGitOverride) return (await __bloatGitOverride(args, cwd)).trim()
  // `maxBuffer` is raised because `rev-list --objects --all` on a large repo
  // can exceed the 1 MiB default and would otherwise fail with ENOBUFS.
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  })
  return stdout
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Human-readable byte size (e.g. `1.4 MB`). */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '?'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`
}

/**
 * Parse the output of
 *   git rev-list --objects --all
 *     | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)'
 *
 * Each line is `blob <oid> <size> <path>`. Non-blob objects (commit/tree/tag)
 * and lines without a usable size are skipped; the path may be empty for
 * objects reached only through a tree-less reference.
 */
export function parseBatchCheck(output: string): Array<{ oid: string; size: number; path: string }> {
  const out: Array<{ oid: string; size: number; path: string }> = []
  for (const raw of output.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const m = line.match(/^(\w+)\s+([0-9a-fA-F]{7,64})\s+(\d+)(?:\s+(.*))?$/)
    if (!m) continue
    const [, type, oid, sizeText, rest] = m
    if (type !== 'blob') continue
    const size = Number(sizeText)
    if (!Number.isFinite(size)) continue
    out.push({ oid, size, path: (rest ?? '').trim() })
  }
  return out
}

/** Find the commit that first introduced `path` carrying `oid`, if any. */
async function findIntroducingCommit(
  root: string,
  oid: string,
  path: string,
): Promise<BloatEntry['commit']> {
  // `--find-object` reports commits that changed the number of occurrences of
  // an object. Restricting to the recorded path keeps the walk cheap; `--all`
  // is the fallback for a blob whose path is unknown (or that was introduced
  // under a different name). `--diff-filter=A` would miss blobs that merely
  // reappear, so it is deliberately not used.
  const queries: string[][] = []
  if (path) {
    queries.push(['log', '--find-object', oid, '--format=%H%x1f%s%x1f%aI', '--', path])
  }
  queries.push(['log', '--find-object', oid, '--format=%H%x1f%s%x1f%aI', '--all'])

  for (const args of queries) {
    let raw: string
    try {
      raw = await git(args, root)
    } catch {
      continue // e.g. --find-object unsupported on very old git
    }
    // `git log` prints newest-first; the earliest introduction is the last line.
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean)
    const last = lines[lines.length - 1]
    if (!last) continue
    const [hash, subject, date] = last.split('\x1f')
    if (hash) {
      return { hash, subject: subject ?? '', date: date ?? '' }
    }
  }
  return undefined
}

/** Total blob bytes + count, from `git count-objects -v`. Best effort. */
async function readObjectTotals(root: string): Promise<{ bytes: number; blobs: number } | null> {
  try {
    const raw = await git(['count-objects', '-v'], root)
    const sizeMatch = raw.match(/^size-pack:\s*(\d+)/m)
    const inPackMatch = raw.match(/^in-pack:\s*(\d+)/m)
    const looseMatch = raw.match(/^count:\s*(\d+)/m)
    if (!sizeMatch) return null
    const packs = Number(sizeMatch[1]) * 1024 // size-pack is in KiB
    const loose = (Number(looseMatch?.[1]) || 0) * 1024
    const blobCount = (Number(inPackMatch?.[1]) || 0) + (Number(looseMatch?.[1]) || 0)
    return { bytes: packs + loose, blobs: blobCount }
  } catch {
    return null
  }
}

export interface BloatOptions {
  /** Rank at most this many blobs (default 20). */
  topN?: number
  /** Skip the per-blob introducing-commit lookup (faster on huge repos). */
  skipCommitLookup?: boolean
}

export class NotARepoError extends Error {
  constructor(dir: string) {
    super(
      `not a git repository: ${dir}\n` +
      'tm_git_bloat analyses a repository\'s object database. Run it from inside a ' +
      'git work tree (or point it at one) — there is nothing to diagnose here.',
    )
    this.name = 'NotARepoError'
  }
}

/**
 * Diagnose the largest blobs reachable from all refs of the repo containing
 * `dir`. Pure reads; safe to run at any time.
 */
export async function analyzeGitBloat(dir: string, opts: BloatOptions = {}): Promise<BloatReport> {
  const topN = opts.topN && opts.topN > 0 ? opts.topN : BLOAT_TOP_N
  // Resolve via git.ts so the "not a repo" path is identical to the gate's
  // notion of a repo (and shares the same override seam in tests).
  const root = await repoRoot(dir)
  if (!root) throw new NotARepoError(dir)
  // The override seam replaces git.ts's git(), so honour it for root too when
  // a test injects non-repo behaviour.

  let batch: string
  let revList: string
  try {
    revList = await git(['rev-list', '--objects', '--all'], root)
    // Empty repo (no commits): nothing to analyse, and cat-file with empty
    // stdin is an error — return an empty report instead.
    if (!revList.trim()) {
      return { root, totalBlobBytes: 0, totalBlobs: 0, entries: [] }
    }
    if (__bloatGitOverride) {
      // The seam cannot feed stdin, so route the batch through `--batch-all-objects`
      // restricted to blobs — semantically the reachable set minus unreachable
      // garbage, which is what this diagnosis is about anyway.
      batch = await git(
        ['cat-file', '--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)', '--batch-all-objects'],
        root,
      )
    } else {
      batch = await catFileBatchCheck(root, revList)
    }
  } catch (err) {
    throw new Error(`git object scan failed in ${root}: ${errMsg(err)}`)
  }

  const parsed = parseBatchCheck(batch)
  // A blob reachable from several paths appears once per path; keep the
  // cheapest attribution per oid and sum nothing twice.
  const byOid = new Map<string, { oid: string; size: number; path: string }>()
  let totalBlobBytes = 0
  for (const item of parsed) {
    if (!byOid.has(item.oid)) {
      byOid.set(item.oid, item)
      totalBlobBytes += item.size
    }
  }

  const sorted = [...byOid.values()].sort((a, b) => b.size - a.size).slice(0, topN)
  const entries: BloatEntry[] = []
  for (let i = 0; i < sorted.length; i++) {
    const item = sorted[i]
    const commit = opts.skipCommitLookup
      ? undefined
      : await findIntroducingCommit(root, item.oid, item.path)
    entries.push({ rank: i + 1, oid: item.oid, path: item.path, size: item.size, commit })
  }

  return { root, totalBlobBytes, totalBlobs: byOid.size, entries }
}

/** Pipe `rev-list --objects --all` into `cat-file --batch-check` (one spawn). */
function catFileBatchCheck(root: string, revList: string): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const child = execFile(
      'git',
      ['cat-file', '--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)'],
      { cwd: root, timeout: GIT_TIMEOUT_MS, maxBuffer: MAX_BUFFER },
      (err, stdout) => {
        if (err) reject(err)
        else resolvePromise(stdout)
      },
    )
    child.stdin?.end(revList)
  })
}

/** Render a BloatReport as the human/agent-facing table. */
export function formatBloatReport(report: BloatReport): string {
  const lines: string[] = []
  lines.push(`=== TM-Guard .git bloat diagnosis (read-only) ===`)
  lines.push('')
  lines.push(`Repository            : ${report.root}`)
  lines.push(`Reachable blobs       : ${report.totalBlobs} (${formatBytes(report.totalBlobBytes)} uncompressed)`)
  const totals = report.entries.reduce((sum, e) => sum + e.size, 0)
  lines.push(`Top ${report.entries.length} blobs          : ${formatBytes(totals)}`)
  lines.push('')

  if (report.entries.length === 0) {
    lines.push('No reachable blob objects found — nothing to diagnose.')
    return lines.join('\n')
  }

  lines.push('Rank  Size        Path                                     Introduced by')
  lines.push('----  ----------  ---------------------------------------  -------------')
  for (const e of report.entries) {
    const rank = String(e.rank).padEnd(4)
    const size = formatBytes(e.size).padEnd(10)
    const path = (e.path || '(no path recorded)').slice(0, 39).padEnd(39)
    let commit = '(not attributed)'
    if (e.commit) {
      const short = e.commit.hash.slice(0, 12)
      const subject = e.commit.subject.replace(/\s+/g, ' ').slice(0, 40)
      commit = `${short} ${subject}`
    }
    lines.push(`${rank}  ${size}  ${path}  ${commit}`)
  }

  lines.push('')
  lines.push('READ-ONLY DIAGNOSIS — no history was modified. Shrinking .git requires')
  lines.push('manual history rewriting (git filter-repo / BFG) and a force-push, which')
  lines.push('invalidates every existing clone and commit hash. Decide that yourself;')
  lines.push('this tool will not do it. See README § "Diagnosing .git bloat".')
  return lines.join('\n')
}

/**
 * Convenience wrapper used by the tm_git_bloat tool: never throws, always
 * returns text (errors are rendered as guidance instead of a stack trace).
 */
export async function diagnoseGitBloat(dir: string, opts: BloatOptions = {}): Promise<string> {
  try {
    const report = await analyzeGitBloat(dir, opts)
    return formatBloatReport(report)
  } catch (err) {
    if (err instanceof NotARepoError) {
      return `=== TM-Guard .git bloat diagnosis (read-only) ===\n\n${err.message}`
    }
    return (
      '=== TM-Guard .git bloat diagnosis (read-only) ===\n\n' +
      `Diagnosis failed: ${errMsg(err)}\n` +
      'No changes were made (this tool is read-only). Check that git is installed and ' +
      'the repository is readable, then retry.'
    )
  }
}
