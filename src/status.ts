/**
 * tm_status rendering — pure, layered diagnostic output.
 *
 * Why this is its own module: `tm_status` is the single entry point a user
 * reaches for when something is wrong, and the pre-U-08 output was 20 flat
 * lines that interleaved *policy echo* with *health faults*. A reader who saw
 * `UNHEALTHY` had to scroll and guess what to do next. The fix is purely a
 * presentation concern, so it lives here as a pure function of already-gathered
 * facts: deterministic, filesystem-read-only, no dsh/ctx dependency, directly
 * unit-testable.
 *
 * Layout (fixed order, four sections):
 *   1. Health       — state first, faults at the TOP, each with a next command
 *   2. Policy       — what the gate will do (echoed, not decided, here)
 *   3. Data sources — read-only size/rotation measurements of local state
 *   4. Recent       — the last few audit decisions
 *
 * Safety invariant: this module only *formats*. It never changes a gate
 * decision, never writes, and never mutates its inputs. Every fault it prints
 * is accompanied by an executable next step, because "UNHEALTHY" without a
 * remedy is the exact failure mode U-08 exists to remove.
 */

import { existsSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import type { AuditLog, AuditRecord } from './audit.ts'
import type { SnapshotInfo, TmHealth, TmStatus } from './tm.ts'
import { BASELINE_REPORT_FILE } from './baseline-report.ts'

/** How many recent audit decisions the 【Recent】 section shows. */
export const RECENT_STATUS_ITEMS = 5

/** Rotation generations scanned when reporting audit generations. */
const MAX_ROTATED_GENERATIONS = 20

/**
 * The config slice tm_status echoes. Deliberately structural (not the full
 * plugin config type) so tests can build one without importing index.ts.
 */
export interface StatusConfigView {
  protectedPaths: string[]
  denyReadPaths: string[]
  denyNetwork: boolean
  denySystem: boolean
  failClosed: boolean
  requireTaskSnapshot: boolean
  autoApprove: boolean
  snapshotCooldownSeconds: number
}

export interface StatusInput {
  /** False on non-macOS hosts (U-19): TM cannot exist, plugin runs limited. */
  platformSupported: boolean
  /** `process.platform` value, for the header line. */
  platform: string
  health: TmHealth
  status: TmStatus
  latest: SnapshotInfo | null
  config: StatusConfigView
  audit: AuditLog
  /** Total records across all retained generations. */
  auditCount: number
  /** Records representing a real write (allow + target paths). */
  writeCount: number
  /** Most recent decisions, newest first. */
  recentDecisions: AuditRecord[]
}

/* ------------------------------------------------------------------ */
/* Measurement helpers (read-only; every one failure-tolerant)          */
/* ------------------------------------------------------------------ */

/** Human-readable byte size. Deterministic and locale-independent. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'unknown'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`
}

/** Size of a file, or null when it does not exist / cannot be stat'ed. */
function fileSize(path: string): number | null {
  try {
    return statSync(path).size
  } catch {
    return null
  }
}

/** Number of regular files directly inside a directory (non-recursive). */
function countFiles(dir: string): number | null {
  try {
    return readdirSync(dir, { withFileTypes: true }).filter((e) => e.isFile())
      .length
  } catch {
    return null
  }
}

/** Total size of a directory tree, best-effort and depth-capped. */
function dirSize(root: string, maxDepth = 3): number | null {
  let total = 0
  let sawAnything = false
  const walk = (dir: string, depth: number): void => {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return // unreadable subtree contributes nothing rather than failing
    }
    for (const entry of entries) {
      const full = join(dir, entry.name)
      try {
        if (entry.isDirectory()) {
          if (depth < maxDepth) walk(full, depth + 1)
        } else if (entry.isFile()) {
          total += statSync(full).size
          sawAnything = true
        }
      } catch {
        // Vanished mid-walk or unreadable: skip.
      }
    }
  }
  walk(root, 0)
  return sawAnything ? total : null
}

/** Rotation generations present on disk, newest first (`.1`, `.2`, …). */
function auditGenerations(audit: AuditLog): string[] {
  const out: string[] = []
  for (let i = 1; i <= MAX_ROTATED_GENERATIONS; i++) {
    const p = `${audit.path}.${i}`
    if (existsSync(p)) out.push(`.${i}`)
  }
  return out
}

/* ------------------------------------------------------------------ */
/* Fault model — each fault pairs a problem with a next action          */
/* ------------------------------------------------------------------ */

interface Fault {
  /** What is wrong, stated in one line. */
  problem: string
  /** The exact command or check that moves the user forward. */
  next: string
}

/**
 * Derive the ordered fault list. Ordering is deliberate: anything that BLOCKS
 * writes comes before anything that merely degrades convenience, so the first
 * line the user reads is the one that unblocks them.
 *
 * On a platform without TM there are no TM faults to report — TM is absent,
 * not broken (U-19). Reporting it as fixable would send the user chasing a
 * `tmutil` that cannot be installed.
 */
function deriveFaults(input: StatusInput): Fault[] {
  const { health, status, platformSupported, latest, audit } = input
  const faults: Fault[] = []

  if (!platformSupported) return faults

  if (!health.healthy) {
    // Order matters within the group too: the destination is the root cause
    // that makes the snapshot checks moot, so it is reported first.
    if (!health.destinationConfigured) {
      faults.push({
        problem: 'Time Machine destination is NOT configured',
        next: 'open System Settings → General → Time Machine and select a backup disk, then re-run tm_status (check with: tmutil destinationinfo)',
      })
    }
    if (!health.hasSnapshots) {
      faults.push({
        problem: 'No local Time Machine snapshots exist (nothing to roll back to)',
        next: 'run tm_snapshot to create a checkpoint now, or tm_backup to complete a backup to the disk',
      })
    }
    if (!health.workspaceProtected) {
      faults.push({
        problem: `Workspace paths NOT protected by Time Machine: ${health.unprotectedPaths.join(', ')}`,
        next: 'remove the paths from the Time Machine exclusion list (System Settings → General → Time Machine → Options), or add them to tm-guard protectedPaths only if you accept losing the TM backstop',
      })
    }
    // Any remaining issues are not attributable to a specific branch above;
    // surface them with the generic remedy so none is silently dropped.
    for (const issue of health.issues) {
      const attributed =
        (!health.destinationConfigured && issue.includes('destination')) ||
        (!health.hasSnapshots && issue.includes('No local Time Machine snapshots')) ||
        (!health.workspaceProtected && issue.includes('NOT protected'))
      if (!attributed) {
        faults.push({
          problem: issue,
          next: 'check the Time Machine configuration, then run: tmutil listlocalsnapshots /',
        })
      }
    }
  }

  // Degradations that do not by themselves block writes, reported after the
  // blocking faults so severity ordering stays intact.
  if (health.healthy && !audit) {
    faults.push({
      problem: 'Audit log is unavailable (audit history cannot be read or written)',
      next: 'check that the workspace is writable and re-run tm_status',
    })
  }
  if (health.healthy && status.destinationConfigured && !latest) {
    faults.push({
      problem: 'No usable local snapshot is visible despite a healthy check',
      next: 'run tm_snapshot to create a fresh checkpoint',
    })
  }

  return faults
}

/* ------------------------------------------------------------------ */
/* Renderer                                                             */
/* ------------------------------------------------------------------ */

/**
 * Render the four-section report. Pure: same input ⇒ same output.
 *
 * The section titles are stable machine-readable anchors (regression-tested),
 * which is what lets a user or a future parser find the answer without
 * counting lines.
 */
export function renderStatusReport(input: StatusInput): string {
  const { health, status, latest, config, audit, platformSupported } = input
  const faults = deriveFaults(input)
  const out: string[] = ['=== TM-Guard Status ===']

  /* --- 1. Health (faults first) ---------------------------------- */
  out.push('', '【Health】')
  if (!platformSupported) {
    out.push(`  ⚠️  limited mode — ${input.platform} has no Time Machine (tmutil unavailable)`)
    out.push('      Rollback net: local git baseline only. TM tools and fail-closed TM')
    out.push('      checks are inert; this is a capability limit, not a fault.')
  } else if (faults.length === 0) {
    out.push('  ✅ HEALTHY — Time Machine is a working rollback net')
  } else {
    out.push(`  🚫 UNHEALTHY — ${faults.length} issue${faults.length === 1 ? '' : 's'}, writes may be BLOCKED`)
    faults.forEach((f, i) => {
      out.push(`  ${i + 1}. ${f.problem}`)
      out.push(`     → next: ${f.next}`)
    })
  }
  // Facts that qualify the verdict, always present so the section stands alone.
  out.push(
    `  TM health (fail-closed) : ${
      platformSupported
        ? (health.healthy ? 'HEALTHY ✅' : 'UNHEALTHY 🚫 — writes BLOCKED')
        : 'N/A — no TM on this platform (git baseline is the rollback net)'
    }`,
  )
  out.push(
    `  Platform                : ${
      platformSupported
        ? `${input.platform} — full mode (Time Machine available)`
        : `${input.platform} — limited mode (no TM)`
    }`,
  )
  out.push(
    `  Workspace protected     : ${health.workspaceProtected ? 'YES ✅' : 'NO ⚠️'}`,
  )
  out.push(
    `  Time Machine destination: ${status.destinationConfigured ? 'configured' : 'NOT configured ⚠️'}`,
  )
  out.push(
    `  Local snapshots         : ${status.snapshotCount} available${
      latest ? ` (latest ${latest.date})` : ' ⚠️'
    }`,
  )
  out.push(`  Health checked at       : ${health.checkedAt.toLocaleString()}`)

  /* --- 2. Policy -------------------------------------------------- */
  out.push('', '【Policy】')
  out.push('  Effective gate policy for this session:')
  out.push(`  denyReadPaths           : ${config.denyReadPaths.length} path(s)`)
  if (config.denyReadPaths.length > 0) {
    out.push(`    ${config.denyReadPaths.join(', ')}`)
  } else {
    out.push('    (none — reads are unrestricted; deliberate opt-out)')
  }
  out.push(`  denyNetwork             : ${config.denyNetwork ? 'YES — network ops BLOCKED' : 'no — allowed'}`)
  out.push(`  denySystem              : ${config.denySystem ? 'YES — system/process ops BLOCKED' : 'no — allowed'}`)
  // Spelled "Fail-closed" (not "failClosed") deliberately: this exact line is
  // asserted by the pre-U-08 regression test, and U-08 is a presentation-only
  // change — the label a user already greps for must keep working.
  out.push(`  Fail-closed             : ${config.failClosed ? 'YES (block writes if TM unhealthy)' : 'no'}`)
  out.push(`  Require task snapshot   : ${config.requireTaskSnapshot ? 'YES' : 'no'}`)
  out.push(`  autoApprove             : ${config.autoApprove ? 'YES (prompt-free runs)' : 'no'}`)
  out.push(`  snapshotCooldown        : ${config.snapshotCooldownSeconds}s`)
  out.push(`  Protected dirs (${config.protectedPaths.length})      : ${config.protectedPaths.join(', ') || '(none)'}`)

  /* --- 3. Data sources (sizes measured read-only) ----------------- */
  out.push('', '【Data sources】')
  const auditBytes = fileSize(audit.path)
  const generations = auditGenerations(audit)
  out.push(
    `  audit.jsonl             : ${
      auditBytes === null ? 'absent' : formatBytes(auditBytes)
    } — ${generations.length} rotation generation(s)${
      generations.length > 0 ? ` [${generations.join(', ')}]` : ''
    }`,
  )
  out.push(
    `    ${input.auditCount} records across generations (${input.writeCount} write ops)`,
  )
  out.push(`    path: ${audit.path}`)

  const reportsDir = join(audit.dirPath, 'reports')
  const reportCount = countFiles(reportsDir)
  out.push(
    `  reports/                : ${
      reportCount === null ? 'absent' : `${reportCount} file(s)`
    }`,
  )

  const gitDir = join(resolve(process.cwd()), '.git')
  const gitBytes = dirSize(gitDir)
  out.push(
    `  .git                    : ${
      gitBytes === null ? 'absent (no git baseline here)' : formatBytes(gitBytes)
    }`,
  )

  // First-run baseline report (U-27). Always printed, exists or not: a missing
  // report is itself the answer to "where is my protection-level summary?", and
  // silence would leave the user re-deriving it from the sections above.
  const baselinePath = join(audit.dirPath, BASELINE_REPORT_FILE)
  out.push(
    `  Baseline report         : .tm-guard/${BASELINE_REPORT_FILE} ${
      existsSync(baselinePath) ? '(首次运行生成)' : '(尚未生成 — 重启会话后自动生成)'
    }`,
  )

  /* --- 4. Recent decisions ---------------------------------------- */
  // ignored-file recovery: total git-unrecoverable (ignored) targets across
  // the recent window. Optional field — old records contribute 0.
  const recentNoCount = input.recentDecisions.reduce(
    (n, r) => n + (r.gitRecovery?.filter((g) => g.state === 'no').length ?? 0),
    0,
  )
  out.push('', `【Recent】 last ${RECENT_STATUS_ITEMS} audit decision(s), newest first:`)
  if (recentNoCount > 0) {
    out.push(
      `  git-unrecoverable (ignored) targets in recent window: ${recentNoCount} (marked git=no in tm_audit)`,
    )
  }
  if (input.recentDecisions.length === 0) {
    out.push('  (none recorded yet)')
  } else {
    for (const r of input.recentDecisions) {
      const verdict = r.decision === 'deny' ? 'DENY' : 'ALLOW'
      const noCount = r.gitRecovery?.filter((g) => g.state === 'no').length ?? 0
      const gitNo = noCount > 0 ? ` git=no(${noCount})` : ''
      out.push(`  ${r.ts}  ${verdict.padEnd(5)} [${r.category}] ${r.tool}${gitNo}`)
    }
  }

  return out.join('\n')
}
