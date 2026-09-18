/**
 * Verification layer — feedback layer 3 (acceptance check).
 *
 * After a turn completes, independently cross-check the claimed work against
 * ground truth instead of relaying the agent's own summary: produced files
 * really exist and are non-empty, every allowed write stayed inside the
 * protected paths, denied operations left no side effects, and the rollback
 * net (local git baseline + TM snapshots) is in place. Emits a verdict of
 * "verified" (✅) or "issues" (⚠️) appended to the turn report.
 *
 * Pure and deterministic (filesystem reads only — never mutates), so it is
 * unit-testable and safe to run inside the zero-intervention harness.
 */

import { existsSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { AuditRecord } from './audit.ts'

export interface VerifyCheck {
  name: string
  pass: boolean
  detail: string
}

export interface VerifyInput {
  /** Audit records of this turn (activity only). */
  records: AuditRecord[]
  /** Distinct produced/affected paths (write targets). */
  artifacts: string[]
  /** Protected path prefixes from config. */
  protectedPaths: string[]
  /** Local TM snapshot count (undefined = unknown). */
  snapshotCount?: number
}

export interface VerifyResult {
  ok: boolean
  checks: VerifyCheck[]
  /** Markdown section appended to the turn report. */
  markdown: string
}

/** Walk up from dir looking for a .git directory. */
function hasGitRoot(dir: string): boolean {
  let d = dir
  while (d && d !== dirname(d)) {
    if (existsSync(join(d, '.git'))) return true
    d = dirname(d)
  }
  return false
}

/**
 * Synchronous directory-boundary prefix check (mirrors tm.ts isPathProtected
 * but without the async tmutil exclusion query — this layer only needs to
 * confirm the write stayed inside the configured prefixes).
 */
function underProtectedPrefix(
  path: string,
  prefixes: string[],
): boolean {
  const normalized = path.startsWith('~')
    ? path.replace('~', process.env.HOME ?? '')
    : path
  const absolute = normalized.startsWith('/')
    ? normalized
    : `${process.cwd()}/${normalized}`
  return prefixes.some((p) => {
    const pref = p.replace(/\/+$/, '')
    return absolute === pref || absolute.startsWith(pref + '/')
  })
}

export function verifyTurn(input: VerifyInput): VerifyResult {
  const { records, artifacts, protectedPaths, snapshotCount } = input
  const checks: VerifyCheck[] = []

  const writes = records.filter(
    (r) =>
      r.decision === 'allow' &&
      r.category === 'file_write' &&
      r.targetPaths.length > 0,
  )
  const deniedWrites = records.filter(
    (r) => r.decision === 'deny' && r.category === 'file_write',
  )

  /* 1 — Artifacts really exist and are non-empty. */
  const missing = artifacts.filter((p) => !existsSync(p))
  const empty = artifacts.filter((p) => {
    try {
      return statSync(p).size === 0
    } catch {
      return false
    }
  })
  checks.push({
    name: '产物存在性',
    pass: missing.length === 0 && empty.length === 0,
    detail:
      artifacts.length === 0
        ? '本轮无写操作，无产物需核验'
        : `${artifacts.length} 个产物：缺失 ${missing.length}，空文件 ${empty.length}`,
  })

  /* 2 — Every allowed write stayed inside the protected prefixes. */
  let allProtected = true
  let badPath = ''
  for (const w of writes) {
    for (const p of w.targetPaths) {
      if (!underProtectedPrefix(p, protectedPaths)) {
        allProtected = false
        badPath = p
        break
      }
    }
    if (!allProtected) break
  }
  checks.push({
    name: '写路径保护',
    pass: allProtected,
    detail: allProtected
      ? `${writes.length} 次写操作均在保护范围内`
      : `越界写（保护外）: ${badPath}`,
  })

  /* 3 — Denied write operations left no files behind. */
  const sideEffects = deniedWrites.filter((d) =>
    d.targetPaths.some((p) => existsSync(p)),
  )
  checks.push({
    name: '拦截无副作用',
    pass: sideEffects.length === 0,
    detail:
      sideEffects.length === 0
        ? `${deniedWrites.length} 次被拦写操作未产生文件`
        : `疑点: ${sideEffects
            .flatMap((s) => s.targetPaths)
            .join('; ')} 存在文件`,
  })

  /* 4 — Rollback net is in place (git baseline near writes + TM snapshots). */
  const gitOk =
    writes.length === 0 || writes.every((w) => hasGitRoot(dirname(w.targetPaths[0])))
  const snapOk = snapshotCount === undefined || snapshotCount > 0
  checks.push({
    name: '回滚就绪',
    pass: gitOk && snapOk,
    detail:
      `git 基线 ${gitOk ? '就绪' : '缺失'}; ` +
      `TM 快照 ${snapshotCount === undefined ? '未知' : `${snapshotCount} 个`}`,
  })

  const ok = checks.every((c) => c.pass)
  const md: string[] = []
  md.push(`## 验收核验（第三层）`)
  md.push(``)
  md.push(`| 检查项 | 结果 | 明细 |`)
  md.push(`|---|---|---|`)
  for (const c of checks) {
    md.push(`| ${c.name} | ${c.pass ? '✅' : '❌'} | ${c.detail.replace(/\|/g, '\\|')} |`)
  }
  md.push(``)
  md.push(
    ok
      ? `**结论：✅ 已核验** — 产物、路径、拦截与回滚就绪均通过独立检查。`
      : `**结论：⚠️ 有疑点** — 下列检查未通过，建议人工复核：${checks
          .filter((c) => !c.pass)
          .map((c) => c.name)
          .join('、')}。`,
  )
  md.push(``)

  return { ok, checks, markdown: md.join('\n') }
}
