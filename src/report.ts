/**
 * Turn completion report — feedback layer 1.
 *
 * Pure, deterministic markdown generator: turns the audit records of one
 * agent turn into a structured completion summary (what was done, what was
 * blocked, changed files, produced artifacts, rollback readiness) plus a
 * one-line console summary. No dsh/ctx dependency, so it is unit-testable
 * and reusable by any harness entry point.
 */

import type { AuditRecord } from './audit.ts'

export interface TurnReportInput {
  /** Agent turn number (1-based). */
  turn: number
  /** ISO timestamp of report generation. */
  now: string
  /** Working directory the turn ran in. */
  cwd: string
  /** Audit records belonging to this turn (tool activity only). */
  records: AuditRecord[]
  /** Optional `git status --short` output (may be '' on failure). */
  gitStatus?: string
  /** Optional number of local TM snapshots available. */
  snapshotCount?: number
}

export interface TurnReport {
  md: string
  summary: string[]
  /** Distinct write-target paths (artifacts) — reused by the verifier. */
  artifacts: string[]
}

/** Category labels for the blocked-operations table. */
function blockLabel(r: AuditRecord): string {
  if (r.category === 'network') return '网络'
  if (r.category === 'system' || r.category === 'process') return '系统/进程'
  if (r.category === 'file_write') {
    if (r.reason.includes('NOT protected')) return '越界写'
    if (r.reason.includes('denyReadPaths')) return '敏感路径'
    return '写操作'
  }
  if (r.category === 'read') return '读操作'
  if (r.category === 'fail-closed') return 'fail-closed'
  if (r.category === 'unknown' || r.category === 'mixed') return '未知操作'
  return String(r.category)
}

/** Extract the first target path of a record for display. */
function firstPath(r: AuditRecord): string {
  return r.targetPaths[0] ?? ''
}

/**
 * Build the completion report for one turn.
 * Deterministic: same records → same markdown.
 */
export function buildTurnReport(input: TurnReportInput): TurnReport {
  const { turn, now, cwd, records, gitStatus, snapshotCount } = input
  const summary: string[] = []

  const activity = records.filter(
    (r) => r.decision === 'allow' || r.decision === 'deny',
  )
  const allowed = activity.filter((r) => r.decision === 'allow')
  const denied = activity.filter((r) => r.decision === 'deny')
  // Only genuine file writes count as writes — read tools may also carry
  // targetPaths since the denyReadPaths work, but they mutate nothing.
  const writes = allowed.filter(
    (r) => r.category === 'file_write' && r.targetPaths.length > 0,
  )

  // Distinct produced/affected paths (write targets, in record order).
  const paths: string[] = []
  for (const w of writes) {
    for (const p of w.targetPaths) {
      if (!paths.includes(p)) paths.push(p)
    }
  }

  // Blocked-op breakdown by label.
  const deniedByLabel = new Map<string, number>()
  for (const d of denied) {
    const label = blockLabel(d)
    deniedByLabel.set(label, (deniedByLabel.get(label) ?? 0) + 1)
  }

  const blockedDesc =
    denied.length === 0
      ? '无'
      : [...deniedByLabel.entries()]
          .map(([k, v]) => `${k}×${v}`)
          .join('、')

  summary.push(
    `turn=${turn} tools=${activity.length} (allow=${allowed.length}/deny=${denied.length}) ` +
      `writes=${writes.length} blocked=${blockedDesc} artifacts=${paths.length}`,
  )

  const md: string[] = []
  md.push(`# dsh-tm-guard 回合完成报告`)
  md.push(``)
  md.push(`- **回合**: ${turn}`)
  md.push(`- **时间**: ${now}`)
  md.push(`- **工作目录**: \`${cwd}\``)
  md.push(``)
  md.push(`## 操作统计`)
  md.push(``)
  md.push(`| 项 | 值 |`)
  md.push(`|---|---|`)
  md.push(`| 工具调用 | ${activity.length}（放行 ${allowed.length} / 拦截 ${denied.length}） |`)
  md.push(`| 文件写入 | ${writes.length} |`)
  md.push(`| 被拦截 | ${blockedDesc} |`)
  if (snapshotCount !== undefined) {
    md.push(`| TM 本地快照 | ${snapshotCount} 个 |`)
  }
  md.push(``)

  if (writes.length > 0) {
    md.push(`## 放行的写操作`)
    md.push(``)
    md.push(`| 时间 | 工具 | 目标路径 | 快照 |`)
    md.push(`|---|---|---|---|`)
    for (const w of writes) {
      const t = (w.ts ?? '').slice(11, 19)
      md.push(`| ${t} | ${w.tool} | \`${firstPath(w)}\` | ${w.snapshotId ?? '-'} |`)
    }
    md.push(``)
  }

  if (paths.length > 0) {
    md.push(`## 产物 / 变更路径`)
    md.push(``)
    for (const p of paths) {
      md.push(`- \`${p}\``)
    }
    md.push(``)
  }

  if (denied.length > 0) {
    md.push(`## 被拦截的操作`)
    md.push(``)
    md.push(`| 时间 | 工具 | 类型 | 原因 |`)
    md.push(`|---|---|---|---|`)
    for (const d of denied) {
      const t = (d.ts ?? '').slice(11, 19)
      const reason = d.reason.replace(/\|/g, '\\|').slice(0, 90)
      md.push(`| ${t} | ${d.tool} | ${blockLabel(d)} | ${reason} |`)
    }
    md.push(``)
  }

  if (gitStatus !== undefined && gitStatus.trim().length > 0) {
    md.push(`## git 工作区状态`)
    md.push(``)
    md.push('```text')
    md.push(gitStatus.trim())
    md.push('```')
    md.push(``)
  }

  md.push(`---`)
  md.push(`*由 dsh-tm-guard 自动生成（反馈层 1：完成反馈）。审计全文：见 .tm-guard/audit.jsonl。*`)

  return { md: md.join('\n'), summary, artifacts: paths }
}
