/**
 * dsh-tm-guard — Time-Machine-backed autonomous agent permission gate.
 *
 * Allows operations that can be rolled back via macOS Time Machine
 * local snapshots; blocks everything else.  Enables zero-intervention
 * autonomous agent runs within a TM-protected workspace.
 *
 * Extension points used:
 *   - tools/pre-execute  : permission gate (allow/deny) + audit logging
 *   - ctx.tools.register : tm_snapshot / tm_rollback / tm_audit / tm_status
 *                          / tm_git_bloat (read-only .git diagnosis)
 *   - ctx.systemPrompt   : injects operating-mode guidance + workflow
 *
 * Features (v0.1.0):
 *   - Audit log (JSONL) records every gate decision for post-hoc traceability
 *   - Multi-strategy rollback (auto-mount → tmutil → manual mount → instructions)
 *   - "Roll back last operation" via audit log
 *   - Enforced agent workflow: snapshot → modify → verify → rollback on failure
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'

import {
  createSnapshot,
  listSnapshots,
  latestSnapshot,
  isPathProtected,
  getTmStatus,
  getTmHealth,
  invalidateHealthCache,
  rollbackPath,
  rollbackPaths,
  startBackup,
  getBackupStatus,
  type SnapshotInfo,
  type RollbackResult,
  type TmHealth,
} from './tm.ts'
import {
  classifyToolCall,
  decide,
  type GateDecision,
} from './classifier.ts'
import { scanCommandForEgress } from './scan-scripts.ts'
import {
  DEFAULT_SENSITIVE_PATHS,
  mergeDenyReadPaths,
} from './sensitive-paths.ts'
import { AuditLog, AUDIT_DEFAULTS } from './audit.ts'
import {
  readState,
  writeState,
  resolveWatermark,
  watermarkOf,
} from './state.ts'
import { ensureGitBaseline, commitCheckpoint } from './git.ts'
import { diagnoseGitBloat, BLOAT_TOP_N } from './bloat.ts'
import { buildTurnReport, pruneReports } from './report.ts'
import { renderStatusReport, RECENT_STATUS_ITEMS } from './status.ts'
import {
  BASELINE_REPORT_FILE,
  collectBaselineFacts,
  ensureBaselineReport,
} from './baseline-report.ts'
import { verifyTurn } from './verify.ts'
import { dirname, join, resolve } from 'node:path'
import { execSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'

/* ------------------------------------------------------------------ */
/* Plugin configuration                                                */
/* ------------------------------------------------------------------ */

export interface TmGuardConfig {
  /**
   * Path prefixes that are protected by Time Machine.
   * Defaults to the current working directory (workspace root).
   */
  protectedPaths: string[]
  /**
   * Minimum seconds between automatic pre-operation snapshots.
   * Default 30 seconds.  Set to 0 to create a fresh TM snapshot before
   * EVERY write operation (finest rollback granularity).  Higher values
   * reduce snapshot overhead but group multiple writes under one checkpoint.
   */
  snapshotCooldownSeconds: number
  /**
   * When true, network operations are denied (default true).
   */
  denyNetwork: boolean
  /**
   * When true, system/process operations are denied (default true).
   */
  denySystem: boolean
  /**
   * Sensitive path prefixes (absolute or ~-prefixed) that the agent may not
   * READ — e.g. '~/.ssh', '~/.aws', '~/Library/Keychains'. Any operation
   * (read or write) referencing a path under one of these prefixes is denied
   * and audited. This closes the zero-intervention gap where the agent runs
   * with the user's full read access: credentials, keys and configs outside
   * the workspace stay out of reach.
   *
   * ADDITIVE by default (U-18c): entries here are APPENDED to
   * DEFAULT_SENSITIVE_PATHS. Set `denyReadPathsReplace: true` to make this
   * list replace the defaults outright. An explicit empty list (`[]`) with
   * replace=true disables the restriction entirely.
   */
  denyReadPaths: string[]
  /**
   * When true, `denyReadPaths` REPLACES `DEFAULT_SENSITIVE_PATHS` instead of
   * being appended to it. Default false (additive) because replacement is the
   * fail-open direction: a profile that adds one project path would otherwise
   * silently drop every cloud/agent credential entry. Use this only when you
   * are deliberately curating the whole list.
   */
  denyReadPathsReplace: boolean
  /**
   * Additional tool names to always allow (bypass classification).
   */
  extraAllowTools: string[]
  /**
   * Additional tool names to always deny.
   */
  extraDenyTools: string[]
  /**
   * When true, log every gate decision to the harness console.
   */
  verbose: boolean
  /**
   * When true, require the agent to create a snapshot before any
   * multi-step task.  Enforced via system prompt guidance.
   */
  requireTaskSnapshot: boolean
  /**
   * When true (default), block ALL write operations if Time Machine
   * is unhealthy (no destination, no snapshots, or workspace not
   * protected).  This is the fail-closed safety net: if the rollback
   * mechanism is broken, the agent must not make changes.
   */
  failClosed: boolean
  /**
   * When true, also block read operations when TM is unhealthy.
   * Default false — reads are harmless and the agent needs them to
   * diagnose the issue.
   */
  failClosedBlockReads: boolean
  /**
   * When true (default), generate a structured markdown completion report
   * after every agent turn that had tool activity: what was allowed/blocked,
   * changed files, produced artifacts, rollback readiness. Reports are
   * written next to the audit log under `.tm-guard/reports/turn-<ts>.md` and
   * a one-line summary prints to the harness console. This is feedback
   * layer 1 (completion feedback); layer 2 (real-time alerts) is separate.
   */
  turnReports: boolean
  /**
   * How many turn reports to keep under `.tm-guard/reports` (default 200).
   * Reports are pure derived display artifacts — the audit log remains the
   * source of truth for `tm_rollback` — so pruning them is always safe. This
   * threshold is ANDed with `reportsRetainDays`: a report is deleted only when
   * it is both beyond this count and older than that age.
   */
  reportsRetainCount: number
  /**
   * Minimum age in days before a turn report becomes eligible for deletion
   * (default 30). Intersected with `reportsRetainCount` so lightly-used
   * workspaces are not wiped purely for being old. `0` disables the age gate
   * (count alone decides).
   */
  reportsRetainDays: number
  /**
   * When true, run a BLOCKING full Time Machine backup to the backup disk
   * (tm_backup, wait) before EVERY file write. This gives each write a
   * restore point that tm_rollback can read back WITHOUT root/sudo — at the
   * cost of waiting for a backup (tens of seconds to minutes) per write and
   * heavy SD-card use. When false (default), an instant local APFS snapshot
   * is taken before writes instead (sub-second, but reading it back needs
   * root or the Time Machine UI).
   */
  blockingBackupBeforeWrite: boolean
  /**
   * When true (default), every file write is gated at the tool layer on a local
   * git baseline: the target directory must be inside a git work tree with a
   * committed baseline, else the plugin creates one (git init + .gitignore +
   * baseline commit). Local git is the instant, root-free, offline rollback
   * net. Writes where a baseline cannot be established are denied.
   */
  requireGitBaseline: boolean
  /**
   * When true (default), auto-approve the dsh approval/request waterfall with
   * 'allowed-once' so the agent runs with zero human prompts. This is safe ONLY
   * because the tools/pre-execute gate is registered with prepend (it runs
   * first and denies anything non-rollback-able before a later gate can raise
   * an approval 'ask'); ops reaching the approval stage have already passed the
   * gate. Set false to let escalation asks fall through to the user/deny.
   */
  autoApprove: boolean
  /**
   * Rotate `.tm-guard/audit.jsonl` once it exceeds this many bytes (default
   * 10 MiB ≈ 22.9k records at 457 B/record). Rotation keeps the rollback
   * history readable instead of letting one unbounded file grow forever.
   * `0` (or negative) disables rotation entirely.
   */
  auditMaxBytes: number
  /**
   * How many rotated generations to keep as `audit.jsonl.1` … `audit.jsonl.N`
   * (default 5, where `.1` is the NEWEST). With the default 10 MiB threshold
   * this is a ≈50 MiB / ≈115k-record history window. The oldest generation is
   * deleted once the window is full — that deletion is irreversible.
   */
  auditRetainFiles: number
  /**
   * Hard ceiling across the current log plus every rotated generation
   * (default 100 MiB = 2× headroom over `auditRetainFiles × auditMaxBytes`).
   * This is an abnormal-case backstop, not the normal window control: with
   * headroom, the generation count trips first and this ceiling stays idle.
   * Were it equal to retain×max, every single new record would force deleting
   * an entire oldest generation.
   */
  auditTotalMaxBytes: number
}

export const DEFAULT_CONFIG: TmGuardConfig = {
  protectedPaths: [process.cwd()],
  snapshotCooldownSeconds: 30,
  denyNetwork: true,
  denySystem: true,
  // Sensitive-path read restriction. The base list lives in
  // src/sensitive-paths.ts so it can be reviewed (and extended) as pure data,
  // independently of the gate logic. Keep it a defensive copy: DEFAULT_CONFIG
  // is exported, and a caller mutating `DEFAULT_CONFIG.denyReadPaths` in place
  // must not be able to corrupt the module-level constant for later applies.
  denyReadPaths: [...DEFAULT_SENSITIVE_PATHS],
  // Additive by default — user entries are APPENDED to the base list. See the
  // TmGuardConfig doc comment for why replacement is the opt-in direction.
  denyReadPathsReplace: false,
  extraAllowTools: [],
  extraDenyTools: [],
  verbose: true,
  requireTaskSnapshot: true,
  failClosed: true,
  failClosedBlockReads: false,
  turnReports: true,
  // Report retention: reports are derived display artifacts (no rollback
  // dependency), so bounding them is safe. Count and age are ANDed — see
  // pruneReports() in report.ts for why an intersection beats a union.
  reportsRetainCount: 200,
  reportsRetainDays: 30,
  // Default off: local git is the instant, root-free rollback mechanism (see the
  // system-prompt workflow). Set true to instead run a blocking (~1 min) TM backup
  // before every state-changing op for non-git directories.
  blockingBackupBeforeWrite: false,
  // Tool-layer safety net: every file write requires a committed local-git
  // baseline (auto-created if absent). This is what makes rollback instant,
  // offline, and root-free; Time Machine remains the backstop for git's blind
  // spots (metadata, ignored files, git-cleaned files, disk failure).
  requireGitBaseline: true,
  // Zero-intervention: auto-answer dsh's approval prompts for ops that already
  // passed the (prepended) TM-Guard gate.
  autoApprove: true,
  // Audit rotation. Values come from src/audit.ts so the single source of truth
  // travels with the code that implements the steps. readAll() splices the
  // generations, so rotation does not break rollback targeting — but the first
  // rotation on a long-lived workspace does irreversibly cut old history once
  // the retention window fills (see README "audit log rotation").
  auditMaxBytes: AUDIT_DEFAULTS.maxBytes,
  auditRetainFiles: AUDIT_DEFAULTS.retainFiles,
  auditTotalMaxBytes: AUDIT_DEFAULTS.totalMaxBytes,
}

/* ------------------------------------------------------------------ */
/* Snapshot throttling + failure tracking                             */
/* ------------------------------------------------------------------ */

let lastSnapshotTime = 0
let consecutiveSnapshotFailures = 0

async function maybeSnapshot(cooldownSeconds: number): Promise<string | null> {
  const now = Date.now()
  if (now - lastSnapshotTime < cooldownSeconds * 1000) {
    return null
  }
  try {
    const date = await createSnapshot()
    lastSnapshotTime = now
    consecutiveSnapshotFailures = 0
    invalidateHealthCache()
    return date
  } catch (err) {
    consecutiveSnapshotFailures++
    const errMsg = err instanceof Error ? err.message : String(err)
    const hint = /permission|denied|not privileged|eperm|eacces/i.test(errMsg)
      ? ' (snapshot creation denied: grant Full Disk Access to your terminal/dsh, or configure sudo NOPASSWD for tmutil localsnapshot)'
      : ''
    console.warn(
      `[tm-guard] Failed to create TM snapshot (attempt ${consecutiveSnapshotFailures}): ${errMsg}${hint}`,
    )
    if (consecutiveSnapshotFailures >= 5) {
      console.warn(
        '[tm-guard] ⚠️  TM snapshot creation has failed 5+ times consecutively. ' +
        'Writes will proceed but may not have fresh rollback points. ' +
        'Run tm_status to diagnose.',
      )
    }
    return null
  }
}

/* ------------------------------------------------------------------ */
/* Plugin definition                                                   */
/* ------------------------------------------------------------------ */

export const name = 'tm-guard'
export const inject = ['tools']

/**
 * Normalize raw cordis.patch.yml values: a hand-edited config can pass a
 * string where an array belongs, a number where a boolean belongs, etc.
 * Plugins must degrade to defaults instead of crashing or silently flipping
 * policy (e.g. denyNetwork: 0 treated as false).
 *
 * `undefined` means "field absent" and falls back to the default; `[]` means
 * "explicitly empty" and is preserved. That distinction is what keeps
 * `denyReadPaths: []` working as the documented disable switch.
 */
function normalizeArray(v: unknown, fallback: string[]): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : fallback
}
function normalizeBool(v: unknown, fallback: boolean): boolean {
  return typeof v === 'boolean' ? v : fallback
}
function normalizeNumber(v: unknown, fallback: number): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

/**
 * Build the report filename with millisecond precision.
 *
 * The old second-precision stamp (`slice(0, 19)`) meant two turns finishing in
 * the same second wrote to the same path and the second silently overwrote the
 * first. Milliseconds make that practically impossible, and the result stays
 * lexicographically sortable (same `YYYY-MM-DDTHH-mm-ss` prefix as before), so
 * prune-by-mtime and glob matching still work.
 */
export function turnReportFileName(now: Date = new Date()): string {
  const stamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 23)
  return `turn-${stamp}.md`
}

export function apply(ctx: Context, rawConfig?: Partial<TmGuardConfig>) {
  const config: TmGuardConfig = {
    ...DEFAULT_CONFIG,
    ...rawConfig,
    protectedPaths: normalizeArray(rawConfig?.protectedPaths, DEFAULT_CONFIG.protectedPaths),
    // Additive merge (U-18c): the raw value is passed through unnormalized so
    // that `undefined` (absent → pure defaults), `[]` (explicit → no additions,
    // or full disable with replace=true) and a real list stay distinguishable.
    // mergeDenyReadPaths validates entry types itself.
    denyReadPaths: mergeDenyReadPaths(
      rawConfig?.denyReadPaths,
      normalizeBool(rawConfig?.denyReadPathsReplace, DEFAULT_CONFIG.denyReadPathsReplace),
    ),
    denyReadPathsReplace: normalizeBool(rawConfig?.denyReadPathsReplace, DEFAULT_CONFIG.denyReadPathsReplace),
    extraAllowTools: normalizeArray(rawConfig?.extraAllowTools, DEFAULT_CONFIG.extraAllowTools),
    extraDenyTools: normalizeArray(rawConfig?.extraDenyTools, DEFAULT_CONFIG.extraDenyTools),
    denyNetwork: normalizeBool(rawConfig?.denyNetwork, DEFAULT_CONFIG.denyNetwork),
    denySystem: normalizeBool(rawConfig?.denySystem, DEFAULT_CONFIG.denySystem),
    failClosed: normalizeBool(rawConfig?.failClosed, DEFAULT_CONFIG.failClosed),
    failClosedBlockReads: normalizeBool(rawConfig?.failClosedBlockReads, DEFAULT_CONFIG.failClosedBlockReads),
    verbose: normalizeBool(rawConfig?.verbose, DEFAULT_CONFIG.verbose),
    requireTaskSnapshot: normalizeBool(rawConfig?.requireTaskSnapshot, DEFAULT_CONFIG.requireTaskSnapshot),
    requireGitBaseline: normalizeBool(rawConfig?.requireGitBaseline, DEFAULT_CONFIG.requireGitBaseline),
    autoApprove: normalizeBool(rawConfig?.autoApprove, DEFAULT_CONFIG.autoApprove),
    turnReports: normalizeBool(rawConfig?.turnReports, DEFAULT_CONFIG.turnReports),
    reportsRetainCount: normalizeNumber(rawConfig?.reportsRetainCount, DEFAULT_CONFIG.reportsRetainCount),
    reportsRetainDays: normalizeNumber(rawConfig?.reportsRetainDays, DEFAULT_CONFIG.reportsRetainDays),
    blockingBackupBeforeWrite: normalizeBool(rawConfig?.blockingBackupBeforeWrite, DEFAULT_CONFIG.blockingBackupBeforeWrite),
    snapshotCooldownSeconds: normalizeNumber(rawConfig?.snapshotCooldownSeconds, DEFAULT_CONFIG.snapshotCooldownSeconds),
    auditMaxBytes: normalizeNumber(rawConfig?.auditMaxBytes, DEFAULT_CONFIG.auditMaxBytes),
    auditRetainFiles: normalizeNumber(rawConfig?.auditRetainFiles, DEFAULT_CONFIG.auditRetainFiles),
    auditTotalMaxBytes: normalizeNumber(rawConfig?.auditTotalMaxBytes, DEFAULT_CONFIG.auditTotalMaxBytes),
  }
  // Empty writable scope is a silent footgun: `protectedPaths: []` means the
  // agent can never write anywhere (every write is denied), which most users
  // read as "no protection". Warn once at apply time; unlike denyReadPaths: []
  // (a documented disable switch), protectedPaths has no "disable" meaning.
  if (config.protectedPaths.length === 0) {
    console.warn(
      '[tm-guard] protectedPaths is empty — no path is writable, every write will be denied. ' +
      'If this is unintended, add your workspace prefix(es).',
    )
  }
  // --- denyReadPaths: additive merge, and say so when it is not ------------
  // Replacement is a fail-open direction (defaults dropped), so it must never
  // be silent. announce the mode AND the effective count, so a config typo
  // that empties the list is visible at load time rather than discovered
  // after a credential read succeeded.
  if (config.denyReadPathsReplace) {
    const dropped = DEFAULT_SENSITIVE_PATHS.filter((p) => !config.denyReadPaths.includes(p))
    if (dropped.length > 0) {
      console.warn(
        `[tm-guard] denyReadPathsReplace=true：用户 denyReadPaths 覆盖默认清单，` +
        `${dropped.length} 条默认敏感路径不再受保护（${dropped.join(', ')}）。` +
        '如非有意，改用追加（去掉 denyReadPathsReplace 或设为 false）。',
      )
    }
  } else if (config.denyReadPaths.length === 0) {
    // Unreachable with the additive merge (defaults are always present), but
    // kept as a guard in case the merge semantics change again: an empty deny
    // list means unrestricted reads of every credential store on the machine.
    console.warn(
      '[tm-guard] denyReadPaths is empty — the agent may read ANY path, ' +
      'including SSH keys and cloud credentials. This is a deliberate opt-out; ' +
      're-enable by removing the empty list.',
    )
  }
  const platformSupported = process.platform === 'darwin'
  // --- Platform capability probe (U-19) -----------------------------------
  // Everything this plugin does on the write side rests on macOS `tmutil`
  // (local APFS snapshots + `tmutil destinationinfo`). On Linux/Windows there
  // is no tmutil at all, and the pre-U-19 behaviour was the worst possible
  // one: a few `tm_*` tools failed at call time while the GATE still spoke
  // fail-closed language ("protected by Time Machine"), so a user could
  // reasonably believe a rollback net existed when none did. Silent
  // degradation in a SAFETY tool is the bug — not the missing platform
  // support. So: state the limitation loudly, keep the gate's git-baseline
  // net working (it is platform-independent), and never claim TM protection.
  if (!platformSupported) {
    console.error(
      `[tm-guard] 当前平台 ${process.platform} 不受支持：本插件依赖 macOS tmutil 本地快照。` +
      '门控已按「无 TM 回滚网」模式运行——写保护仅依赖 git baseline。',
    )
  }

  // One-shot "platform unsupported" reminder (U-19b). The startup banner above
  // scrolls away; a long autonomous run needs the degradation restated at the
  // moment it matters. Warn exactly ONCE per apply() — repeating it on every
  // tool call would bury the gate's real decisions in noise, and a warning
  // that fires constantly is one users learn to ignore.
  let platformWarned = false
  const warnPlatformOnce = (): void => {
    if (platformSupported || platformWarned) return
    platformWarned = true
    console.warn(
      `[tm-guard] ⚠️  平台不支持（${process.platform}）：无 Time Machine 回滚网，` +
      '本轮写操作放行，回滚仅依赖 git baseline。',
    )
  }

  // --- Zero-intervention auto-approval: declare the risk out loud ---------
  // autoApprove=true means this plugin answers DSH approval prompts on the
  // user's behalf, so the *only* thing standing between an operation and
  // execution is the TM-Guard gate itself. That safety argument depends on
  // this plugin's tools/pre-execute hook being registered with `prepend`
  // (it must classify and deny BEFORE any other listener can raise an
  // approval 'ask'). A plugin that registers earlier, or one that bypasses
  // the gate, breaks that assumption silently. Say so once at startup — an
  // implicit auto-answer is exactly the kind of thing that should never be
  // discovered after the fact. See README § "Auto-approval and its blast radius".
  if (config.autoApprove === true) {
    console.warn(
      '[tm-guard] autoApprove=true：将自动应答 dsh approval 询问。' +
      '安全依赖插件 prepend 注册顺序；若与其他权限插件共存请核对。' +
      '详见 README（#auto-approval-and-its-blast-radius）',
    )
  }
  // Fail-open + auto-approve is the one combination with no backstop at all:
  // failClosed=false already lets writes through when no rollback net exists,
  // and autoApprove then removes the human prompt that would have caught it.
  if (config.failClosed === false && config.autoApprove === true) {
    console.warn(
      '[tm-guard] ⚠️  高风险组合：failClosed=false + autoApprove=true — ' +
      '回滚网缺失时写入不再被拦截，且审批询问被自动应答，二者叠加后没有任何人工确认环节。' +
      '建议保留 failClosed=true，或关闭 autoApprove。详见 README #auto-approval-and-its-blast-radius',
    )
  }

  // SINGLE INSTANCE (design §4.2.2): rotation and record() both act on the
  // path this instance resolved, so every audit write in this plugin must go
  // through this one object. Constructing a second AuditLog (e.g. inside a
  // tool handler) would rotate a different file than the one being appended to.
  const audit = new AuditLog(process.cwd(), {
    maxBytes: config.auditMaxBytes,
    retainFiles: config.auditRetainFiles,
    totalMaxBytes: config.auditTotalMaxBytes,
  })

  // Bounded report retention: delete reports that are BOTH beyond the newest
  // `reportsRetainCount` AND older than `reportsRetainDays`. Reports are pure
  // derived display artifacts (the audit log is the rollback source of truth),
  // so this needs no snapshot and can never affect the gate. Wrapped because
  // cleanup must never break plugin load (design R6).
  try {
    const pruned = pruneReports(join(audit.dirPath, 'reports'), {
      retainCount: config.reportsRetainCount,
      retainDays: config.reportsRetainDays,
    })
    if (pruned.deleted.length > 0) {
      console.log(
        `[tm-guard] Pruned ${pruned.deleted.length} old turn report(s); ` +
        `${pruned.kept.length} kept (reportsRetainCount=${config.reportsRetainCount}, reportsRetainDays=${config.reportsRetainDays}).`,
      )
    }
  } catch (err) {
    console.warn(
      `[tm-guard] Report pruning skipped: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  /* -------------------------------------------------------------- */
  /* First-run safety baseline self-check (U-27)                   */
  /* -------------------------------------------------------------- */

  // "What protection level am I actually in?" had no durable answer: tm_status
  // must be asked, and leaves nothing behind. So the first apply() writes one
  // down. Detection is deliberately the *existence of the artifact*, not a
  // state flag in state.json: it is self-describing, survives a wiped state
  // file, and lets a user regenerate by deleting the report.
  //
  // Fully detached from the gate: the report is a display artifact, so a
  // failure here must not stop the plugin from loading (same rule as report
  // pruning above). The probes are read-only, and the git probe specifically
  // does NOT create a baseline — see src/baseline-report.ts.
  try {
    if (!existsSync(join(audit.dirPath, BASELINE_REPORT_FILE))) {
      void collectBaselineFacts({
        platform: process.platform,
        workspace: process.cwd(),
        protectedPaths: config.protectedPaths,
      })
        .then((facts) => {
          const result = ensureBaselineReport(audit.dirPath, {
            platform: process.platform,
            platformSupported: facts.platformSupported,
            workspace: process.cwd(),
            denyReadPaths: config.denyReadPaths,
            protectedPaths: config.protectedPaths,
            denyReadPathsReplace: config.denyReadPathsReplace,
            failClosed: config.failClosed,
            autoApprove: config.autoApprove,
            requireGitBaseline: config.requireGitBaseline,
            status: facts.status,
            health: facts.health,
            git: facts.git,
            generatedAt: new Date(),
          })
          if (result.written) {
            console.log(
              `[tm-guard] 首次运行基线报告已生成: .tm-guard/${BASELINE_REPORT_FILE} — 请查看你的实际保护等级`,
            )
          } else if (result.error) {
            console.warn(`[tm-guard] Baseline report skipped: ${result.error}`)
          }
        })
        .catch((err) => {
          console.warn(
            `[tm-guard] Baseline report skipped: ${err instanceof Error ? err.message : String(err)}`,
          )
        })
    }
  } catch (err) {
    console.warn(
      `[tm-guard] Baseline report skipped: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  /* -------------------------------------------------------------- */
  /* Startup health check (fail-closed)                            */
  /* -------------------------------------------------------------- */

  let startupHealth: TmHealth | null = null
  if (config.failClosed && platformSupported) {
    // Run asynchronously; don't block plugin load. The pre-execute
    // hook will re-check if this hasn't resolved yet.
    getTmHealth(config.protectedPaths)
      .then((health) => {
        startupHealth = health
        if (!health.healthy) {
          console.warn(
            '[tm-guard] ⚠️  Time Machine is NOT healthy. Write operations will be BLOCKED (fail-closed).',
          )
          for (const issue of health.issues) {
            console.warn(`[tm-guard]   - ${issue}`)
          }
        } else if (config.verbose) {
          console.log(
            `[tm-guard] TM health check passed (${health.snapshotCount} snapshots, workspace protected).`,
          )
        }
      })
      .catch((err) => {
        console.warn('[tm-guard] TM health check failed:', err)
      })
  }

  /* -------------------------------------------------------------- */
  /* System prompt: operating mode + enforced workflow             */
  /* -------------------------------------------------------------- */

  try {
    ctx.systemPrompt?.section({
      id: 'tm-guard-mode',
      title: 'TM-Guard Autonomous Mode',
      priority: 100,
      content: [
        '## TM-Guard Autonomous Mode',
        '',
        'You are running in TM-Guard mode. Every tool call is intercepted by a permission gate.',
        ...(platformSupported ? [] : [
          '',
          `**PLATFORM LIMITATION:** this host is ${process.platform}, not macOS. There is no`,
          'Time Machine and no tmutil, so `tm_*` snapshot/rollback tools are inert and the',
          'fail-closed TM check is disabled. The ONLY rollback net is the local git baseline:',
          'commit a checkpoint before the first write in every task, and roll back with',
          '`git reset --hard` + `git clean -fd`. Do not rely on `tm_rollback` here.',
        ]),
        'You work fully autonomously and LOCALLY: there is no human to approve actions, and there',
        'is no network. Your safety net is LOCAL GIT for instant rollback, with Time Machine as a',
        'disaster-recovery backstop.',
        '',
        '### What is allowed (auto-approved)',
        '- Reading files and directories',
        '- Creating, editing, deleting, moving files on protected paths',
        '- Local git: init, add, commit, reset, checkout, restore, clean, stash, branch, diff, log, status (all OFFLINE — no remote needed)',
        '- Running local commands that only read or modify local files',
        '',
        '### What is BLOCKED (irreversible / not local)',
        '- Any network access: curl, wget, ssh, scp, git push/pull/clone/fetch',
        '- Package managers: npm install, pip install, brew install, yarn, cargo',
        '- Process/system management: kill, launchctl, sudo, shutdown, tmutil',
        '- Subagent delegation (cannot verify child operations)',
        '- Reading sensitive paths (SSH keys, cloud credentials, keychains, dotfile secrets): ' +
          (config.denyReadPaths.join(', ') || '(none)'),
        '- Any command not recognized (conservative default = deny)',
        '',
        '### MANDATORY WORKFLOW — local git is your rollback mechanism',
        '',
        'Local git is INSTANT, offline, root-free, and can both revert edits AND delete newly-created',
        'files. Use it for every code/file task. (Time Machine backups are slow and macOS does not',
        'expose a just-finished backup to the command line immediately, so do NOT rely on tm_rollback',
        'for instant undo — it is a last resort.)',
        '',
        '1. **CHECKPOINT (git)**: Before changing anything, ensure a clean committed baseline:',
        '   - If the project is not a git repo: `git init`, then `git add -A && git commit -m "baseline before <task>"`.',
        '   - If it is: `git add -A && git commit -m "checkpoint before <task>"` (commit untracked/modified work so it can be restored).',
        '   These are local commits only; no remote is used or needed.',
        '',
        '2. **MODIFY**: Make your changes freely. File operations are auto-approved on protected paths.',
        '',
        '3. **VERIFY**: Run validation — tests, lint, build, type-check — and READ the results carefully.',
        '',
        '4. **IF VERIFICATION FAILS — roll back YOURSELF, immediately, no human needed**:',
        '   - Revert tracked edits: `git reset --hard HEAD` (back to your checkpoint commit).',
        '   - Remove files you created after the checkpoint: `git clean -fd`.',
        '   - Confirm the tree is clean with `git status`, then report what went wrong. Never leave',
        '     the workspace in a broken state.',
        '',
        '5. **IF VERIFICATION PASSES**: `git add -A && git commit -m "<result>"` to record the good',
        '   state, then report completion.',
        '',
        '### Time Machine backstop (non-git directories / disaster recovery)',
        '- For work that is NOT under git, Time Machine still backs files up (hourly, and via `tm_backup`).',
        '  To recover an older version of a file use `tm_rollback(path=...)`; it restores from the most',
        '  recent mounted backup. Note: TM recovers PREVIOUS versions of files — it cannot undo a file',
        '  created after the last backup, and a backup taken seconds ago may briefly need the Time',
        '  Machine UI (macOS mounts completed backups lazily). Prefer git whenever possible.',
        '',
        '### Rules',
        '- NEVER retry a blocked operation. If denied, adapt to a local-only / offline approach.',
        '- NEVER modify files outside the protected workspace paths.',
        '- ALWAYS make a git checkpoint commit before the first write in any task.',
        '- ALWAYS verify, and on failure ALWAYS `git reset --hard` + `git clean -fd` to your checkpoint before reporting.',
        '- Use `tm_audit` to review this session\'s actions and `tm_status` to check protection.',
      ].join('\n'),
    })
  } catch {
    // systemPrompt service may not be available in all profiles
  }

  /* -------------------------------------------------------------- */
  /* Permission gate: tools/pre-execute + audit logging             */
  /* -------------------------------------------------------------- */

  ctx.on(
    'tools/pre-execute',
    async (exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> => {
      // dsh ToolExecution exposes `name` (tool name) and `arguments` (the
      // validated, frozen model arguments). There is no `exec.tool`/`exec.args`;
      // reading those yields undefined and silently disables the gate.
      const toolName = exec.name ?? 'unknown'
      const args = ((exec.arguments ?? {}) as Record<string, unknown>)

      // Explicit allow/deny lists
      if (config.extraDenyTools.includes(toolName)) {
        audit.record({
          tool: toolName,
          category: 'explicit-deny',
          decision: 'deny',
          reason: 'Tool in deny list',
          targetPaths: [],
          args,
        })
        return {
          kind: 'deny',
          reason: `TM-Guard: tool "${toolName}" is in the deny list.`,
        }
      }
      if (config.extraAllowTools.includes(toolName)) {
        audit.record({
          tool: toolName,
          category: 'explicit-allow',
          decision: 'allow',
          reason: 'Tool in allow list',
          targetPaths: [],
          args,
        })
        if (config.verbose) {
          console.log(`[tm-guard] ALLOW (explicit): ${toolName}`)
        }
        return next()
      }

      // Classify
      const classification = classifyToolCall(
        toolName,
        args,
        config.denyReadPaths,
      )

      // Static egress scan: an interpreter (`python x.py`, `node x.js`,
      // `bash deploy.sh`) is trusted as local_exec by the command classifier,
      // but the SCRIPT it runs may itself call out to the network. Inspect the
      // entry script file, `-c`/`-e` inline code and heredoc bodies on the
      // RAW command before trusting the "local" label. Hits are force-denied
      // so a `denyNetwork=false` config override cannot resurrect smuggled
      // egress; eval/exec/__import__ we cannot prove innocent is downgraded to
      // unknown (conservative deny).
      if (classification.category === 'local_exec') {
        const rawCmd =
          (args.command as string) ??
          (args.input as string) ??
          (args.cmd as string) ??
          (args.code as string) ??
          ''
        if (typeof rawCmd === 'string' && rawCmd) {
          const egress = await scanCommandForEgress(rawCmd)
          if (egress.hits.length > 0) {
            const h = egress.hits[0]
            classification.category = 'network'
            classification.forceDeny = true
            classification.reason +=
              ` [static-script-egress: ${egress.hits.length} network hit(s) at ` +
              `${h.where} (${h.language}): ${h.snippet}]`
            if (config.verbose) {
              console.warn(`[tm-guard] STATIC-EGRESS ${toolName}: ${h.where} — ${h.snippet}`)
            }
          } else if (egress.unverifiable) {
            classification.category = 'unknown'
            classification.reason +=
              ' [static-script-egress: dynamic eval/exec/__import__ — cannot verify no network egress]'
          }
        }
      }

      // Config overrides for network/system
      if (!config.denyNetwork && classification.category === 'network') {
        classification.category = 'file_write'
        classification.reason += ' [network denial disabled by config]'
      }
      if (!config.denySystem && classification.category === 'process') {
        classification.category = 'file_write'
        classification.reason += ' [system denial disabled by config]'
      }

      // Check path protection for file writes
      let pathsProtected = true
      if (classification.category === 'file_write' && classification.targetPaths.length > 0) {
        const checks = await Promise.all(
          classification.targetPaths.map((p) =>
            isPathProtected(p, config.protectedPaths),
          ),
        )
        pathsProtected = checks.every(Boolean)
        if (!pathsProtected) {
          const unprotected = classification.targetPaths.filter(
            (_p, i) => !checks[i],
          )
          classification.reason += ` [unprotected: ${unprotected.join(', ')}]`
        }
      }

      const decision: GateDecision = decide(classification, pathsProtected)

      const isTmInternalTool = toolName.startsWith('tm_')
      const isFileWrite = decision.allow && decision.category === 'file_write'
      const isReadOp = decision.category === 'read'

      /*
       * Tool-layer rollback net for file writes. Local git is the PRIMARY
       * mechanism (instant, offline, root-free); ensure a committed baseline
       * exists (auto-create one if needed). Only if git can't be established do
       * we fall back to Time Machine's health as the backstop. A write proceeds
       * as long as ONE of the two nets is in place; if neither is, it is denied.
       */
      let gitNetReady = false
      if (isFileWrite && !isTmInternalTool) {
        const dirs = new Set<string>()
        for (const p of classification.targetPaths) {
          const abs = p.startsWith('/') ? p : resolve(process.cwd(), p)
          dirs.add(dirname(abs))
        }
        if (dirs.size === 0) dirs.add(process.cwd())
        const dirList = [...dirs]
        if (config.requireGitBaseline) {
          const results = await Promise.all(dirList.map((d) => ensureGitBaseline(d)))
          gitNetReady = results.every((r) => r.ok)

          // Precise rollback: commit any pending work as a checkpoint BEFORE
          // the new write, so `git reset --hard` returns to this exact point.
          for (const r of results) {
            if (r.ok && r.root) {
              await commitCheckpoint(r.root, toolName)
            }
          }

          if (config.verbose) {
            for (let i = 0; i < results.length; i++) {
              if (results[i].ok) {
                console.log(`[tm-guard] git baseline ready: ${results[i].root ?? dirList[i]}`)
              } else {
                console.warn(`[tm-guard] git baseline unavailable in ${dirList[i]}: ${results[i].reason} — relying on Time Machine backstop`)
              }
            }
          }
        }
      }

      /* --- Fail-closed: when git net is absent, a write needs a healthy TM backstop --- */
      const needsTmBackstop = isFileWrite && !gitNetReady
      const blockReads = isReadOp && config.failClosedBlockReads
      // Platform degradation (U-19b): off macOS there is no tmutil, so the
      // TM-health backstop is meaningless — `getTmHealth` can only report
      // UNHEALTHY (the exec fails), which would turn every write that the git
      // net does not cover into a spurious fail-closed denial. Skipping the
      // check is the correct behaviour for "no TM exists"; the git baseline
      // remains the operative net, and the degradation is announced once.
      const tmBackstopEvaluable = platformSupported
      if (!tmBackstopEvaluable && (needsTmBackstop || blockReads)) {
        warnPlatformOnce()
      }
      if (
        config.failClosed &&
        tmBackstopEvaluable &&
        !isTmInternalTool &&
        (needsTmBackstop || blockReads)
      ) {
        const health = await getTmHealth(config.protectedPaths)
        if (!health.healthy) {
          const issueList = health.issues.join('; ')
          const denyReason = gitNetReady === false && isFileWrite
            ? `TM-Guard: no rollback net — a local-git baseline could not be created AND Time Machine is unhealthy (${issueList}). Write denied so the change stays reversible. Fix git or TM (see tm_status), then retry.`
            : `TM-Guard FAIL-CLOSED: Time Machine is unhealthy, operations blocked. Issues: ${issueList}. Run tm_status, fix Time Machine, then retry.`

          if (config.verbose) {
            console.warn(`[tm-guard] FAIL-CLOSED [${decision.category}] ${toolName}: ${issueList}`)
          }
          audit.record({
            tool: toolName,
            category: 'fail-closed',
            decision: 'deny',
            reason: denyReason,
            targetPaths: classification.targetPaths,
            args,
          })
          return { kind: 'deny', reason: denyReason }
        }
      }

      if (config.verbose) {
        const tag = decision.allow ? 'ALLOW' : 'BLOCK'
        console.log(`[tm-guard] ${tag} [${decision.category}] ${toolName}: ${decision.reason}`)
      }

      if (!decision.allow) {
        audit.record({
          tool: toolName,
          category: decision.category,
          decision: 'deny',
          reason: decision.reason,
          targetPaths: classification.targetPaths,
          args,
        })
        return {
          kind: 'deny',
          reason: `TM-Guard: ${decision.reason}`,
        }
      }

      // Any state-changing op is the moment the missing TM net matters most:
      // it is about to be approved, and off macOS the user must know the only
      // thing behind it is the git baseline. Warn once per apply().
      if (isFileWrite || classification.mutates === true) {
        warnPlatformOnce()
      }

      // Pre-mutation checkpoint, enforced at the TOOL layer (the agent cannot
      // bypass this hook). In strict mode it covers file writes AND state-
      // changing local VCS ops (git commit/reset/checkout/clean can discard
      // work); read-only git (status/log/diff) does not need a restore point.
      const isMutation = decision.shouldSnapshot || classification.mutates === true
      let snapshotId: string | undefined
      if (isMutation && !platformSupported) {
        // Off macOS every snapshot strategy shells out to tmutil, which does
        // not exist. `startBackup` would throw and — because the blocking-
        // backup branch is fail-closed — deny EVERY write on a platform the
        // user may be running deliberately. The gate has already decided this
        // write is acceptable on the git net alone, so skip the checkpoint and
        // leave snapshotId undefined (the audit record then honestly shows no
        // TM restore point instead of a fabricated one).
        warnPlatformOnce()
      } else if (isMutation) {
        if (config.blockingBackupBeforeWrite) {
          // User's chosen mode: a BLOCKING full backup to the TM disk before
          // every state-changing op, so a pre-change backup definitely exists
          // on the backup disk. If the backup COMMAND fails, deny the op
          // (fail-closed). On success we record the matching local snapshot id
          // (listable root-free). NOTE: macOS does not leave the just-finished
          // backup mounted for the shell, and the browsable library is mounted
          // lazily (may lag), so immediate command-line restore from this exact
          // point can briefly need the Time Machine UI / root; it becomes
          // root-free once macOS mounts it.
          try {
            await startBackup(true)
            invalidateHealthCache()
            const snap = await latestSnapshot('/')
            snapshotId = snap?.date
            if (config.verbose) {
              console.log(`[tm-guard] Pre-write blocking backup done (checkpoint ${snapshotId ?? 'unknown'})`)
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err)
            if (config.verbose) {
              console.warn(`[tm-guard] Pre-write blocking backup FAILED: ${msg} — denying write`)
            }
            audit.record({
              tool: toolName, category: 'fail-closed', decision: 'deny',
              reason: `Blocking backup failed: ${msg}`,
              targetPaths: classification.targetPaths, args,
            })
            return {
              kind: 'deny',
              reason: `TM-Guard: a blocking Time Machine backup is required before each write but ` +
                `it failed (${msg}). The write is denied so it stays rollback-able. Check the ` +
                `backup disk (SD) with tm_status, then retry.`,
            }
          }
        } else if (config.snapshotCooldownSeconds >= 0) {
          // Default mode: instant local APFS snapshot (sub-second). Reading it
          // back needs root/the TM UI; completed hourly backups are root-free.
          snapshotId = (await maybeSnapshot(config.snapshotCooldownSeconds)) ?? undefined
          if (snapshotId && config.verbose) {
            console.log(`[tm-guard] Pre-op snapshot created: ${snapshotId}`)
          }
        }
      }

      // Audit the allowed operation
      audit.record({
        tool: toolName,
        category: decision.category,
        decision: 'allow',
        reason: decision.reason,
        targetPaths: classification.targetPaths,
        snapshotId,
        args,
      })

      return next()
    },
    // prepend: run the gate FIRST. If a later gate (e.g. the sandbox
    // escalation policy) would return an 'ask', our deny/allow decision is
    // already made — dangerous ops are denied here before any approval prompt
    // can short-circuit, and only ops we allowed can flow to approval.
    true,
  )

  /* -------------------------------------------------------------- */
  /* Feedback layer 1: turn completion reports                       */
  /* -------------------------------------------------------------- */

  // Watermark marking the last audit record already folded into a turn
  // report, persisted to .tm-guard/state.json. Deliberately NOT an array
  // index: `slice(length)` breaks silently as soon as the log rotates or is
  // trimmed (skipped reports, then duplicate reports). See src/state.ts.
  let state = readState(audit.dirPath)

  ctx.on(
    'agent/turn-stopping',
    async (payload: { agent?: unknown; turn?: number }) => {
      if (!config.turnReports) return
      try {
        const all = audit.readAll()
        const { activity, watermarkLost } = resolveWatermark(
          all,
          state.reportWatermark,
        )
        if (watermarkLost) {
          console.warn(
            '[tm-guard] Report watermark is older than the retained audit window ' +
            '(rotated/cleared) — the next report may repeat history once.',
          )
        }

        // Plugin self-test / boot records (explicit-allow) are noise here;
        // report only real gate decisions.
        const real = activity.filter(
          (r) => r.decision === 'allow' || r.decision === 'deny',
        )
        if (real.length === 0) {
          // Nothing to report, but still advance the watermark past any
          // non-decision noise so it cannot accumulate unboundedly.
          if (activity.length > 0) {
            state = { ...state, reportWatermark: watermarkOf(all) }
            writeState(audit.dirPath, state)
          }
          return
        }

        // Best-effort environment context (failures are non-fatal).
        let gitStatus = ''
        try {
          gitStatus = execSync('git status --short', {
            cwd: process.cwd(),
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
          })
        } catch {
          // Not a git work tree or git missing — omit from report.
        }

        let snapshotCount: number | undefined
        try {
          const out = execSync('tmutil listlocalsnapshots /', {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
          })
          snapshotCount = out
            .split('\n')
            .filter((l) => l.includes('.local')).length
        } catch {
          // tmutil unavailable — omit from report.
        }

        const report = buildTurnReport({
          turn: payload.turn ?? 0,
          now: new Date().toISOString(),
          cwd: process.cwd(),
          records: real,
          gitStatus,
          snapshotCount,
        })

        // Feedback layer 3: independent acceptance check (artifacts exist,
        // writes inside protected paths, denials left no side effects,
        // rollback net in place). Verdict is appended to the report.
        const verification = verifyTurn({
          records: real,
          artifacts: report.artifacts,
          protectedPaths: config.protectedPaths,
          snapshotCount,
        })

        const reportDir = join(audit.dirPath, 'reports')
        mkdirSync(reportDir, { recursive: true })
        const file = join(reportDir, turnReportFileName())
        writeFileSync(file, `${report.md}\n${verification.markdown}`, 'utf8')

        // Advance the durable watermark now that the report is on disk. Doing
        // this only after a successful write means a crash mid-report loses
        // nothing: the same records are reported again next turn.
        state = { ...state, reportWatermark: watermarkOf(all) }
        writeState(audit.dirPath, state)

        console.log(`[tm-guard] Turn ${payload.turn ?? 0} report: ${file}`)
        for (const s of report.summary) {
          console.log(`[tm-guard]   ${s}`)
        }
        console.log(
          `[tm-guard]   verification: ${verification.ok ? 'OK (verified)' : 'ISSUES — see report'}`,
        )
      } catch (err) {
        console.warn(
          `[tm-guard] Turn report generation failed: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
    },
  )

  /* -------------------------------------------------------------- */
  /* Zero-intervention auto-approval                                 */
  /* -------------------------------------------------------------- */

  if (config.autoApprove) {
    ctx.on(
      'approval/request',
      // The approval request carries only tool identity, no arguments; that's
      // fine — the prepended pre-execute gate above already classified and
      // allowed/denied the call. Anything reaching this stage was allowed by
      // the gate, so grant it once. Never call next(): the default fallback is
      // 'unavailable' which denies (fail-closed); we answer explicitly.
      (req: { toolName?: string; reason?: string; callId?: unknown }): string => {
        if (config.verbose) {
          console.log(`[tm-guard] AUTO-APPROVE: ${req.toolName ?? 'unknown'}${req.reason ? ` (${req.reason})` : ''}`)
        }
        audit.record({
          tool: req.toolName ?? 'unknown',
          category: 'auto-approve',
          decision: 'allow',
          reason: req.reason ? `auto-approved: ${req.reason}` : 'auto-approved (passed pre-execute gate)',
          targetPaths: [],
        })
        return 'allowed-once'
      },
      true, // prepend: answer before any human-approval listener
    )
  }

  /* -------------------------------------------------------------- */
  /* Registered tools                                               */
  /* -------------------------------------------------------------- */

  // --- tm_snapshot: create a checkpoint ---
  ctx.tools.register(
    defineTool({
      name: 'tm_snapshot',
      description:
        'Create a macOS Time Machine local APFS snapshot as a rollback checkpoint. ' +
        'MANDATORY before making any file modifications. Returns the snapshot date ID. ' +
        'Always pass a descriptive "note" so you can identify this checkpoint later.',
      parameters: {
        note: {
          type: 'string',          description:
            'Label for this checkpoint, e.g. "before-auth-refactor" or "pre-deployment".',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [
          { type: 'text', text: `Time Machine snapshot created: ${value}` },
        ],
      },
      async execute(args: { note?: string }) {
        const date = await createSnapshot()
        lastSnapshotTime = Date.now()
        consecutiveSnapshotFailures = 0
        invalidateHealthCache()
        audit.record({
          tool: 'tm_snapshot',
          category: 'snapshot',
          decision: 'allow',
          reason: `Manual checkpoint${args.note ? ': ' + args.note : ''}`,
          targetPaths: [],
          snapshotId: date,
        })
        return args.note ? `${date} (${args.note})` : date
      },
    }),
  )

  // --- tm_list_snapshots ---
  ctx.tools.register(
    defineTool({
      name: 'tm_list_snapshots',
      description:
        'List all available macOS Time Machine local snapshots with dates. ' +
        'Use to find a rollback point before calling tm_rollback.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        const snaps: SnapshotInfo[] = await listSnapshots('/')
        if (snaps.length === 0) return 'No local Time Machine snapshots found.'
        return snaps
          .map((s) => `  ${s.date}  (${s.createdAt.toLocaleString()})`)
          .join('\n')
      },
    }),
  )

  // --- tm_rollback: restore files ---
  ctx.tools.register(
    defineTool({
      name: 'tm_rollback',
      description:
        'Roll back files to a previous Time Machine snapshot state. ' +
        'Use when verification fails and you need to undo changes. ' +
        'Provide either a specific "path" + optional "snapshot_date", ' +
        'or set "last_operation=true" to roll back the most recent file modification ' +
        'recorded in the audit log.',
      parameters: {
        path: {
          type: 'string',          description:
            'Absolute path of the file or directory to restore. ' +
            'Required unless last_operation is true.',
        },
        snapshot_date: {
          type: 'string',          description:
            'Snapshot date string from tm_list_snapshots (e.g. 2026-09-06-120000). ' +
            'Omit to use the latest snapshot.',
        },
        last_operation: {
          type: 'boolean',          description:
            'If true, roll back the paths from the most recent file-modification ' +
            'operation in the audit log. Ignores "path" when set.',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: {
        path?: string
        snapshot_date?: string
        last_operation?: boolean
      }) {
        // Roll back last operation via audit log
        if (args.last_operation) {
          const writes = audit.writeOperations()
          if (writes.length === 0) {
            return 'No file-modification operations found in audit log. Nothing to roll back.'
          }
          const lastWrite = writes[writes.length - 1]
          const paths = lastWrite.targetPaths
          if (paths.length === 0) {
            return `Last operation (${lastWrite.tool}) had no target paths recorded. ` +
              `Use tm_rollback with an explicit path instead.`
          }
          // Prefer the restore point from a completed blocking tm_backup
          // (root-free, browsable). The localsnapshot id on a write is not
          // readable without sudo, so the backup point is what actually works.
          const backupPoint = audit
            .readAll()
            .filter((r) => r.tool === 'tm_backup' && r.snapshotId)
            .pop()?.snapshotId
          const snapDate = backupPoint ?? args.snapshot_date ?? lastWrite.snapshotId
          const results: RollbackResult[] = await rollbackPaths(paths, snapDate)
          const summary = results
            .map((r) => `  ${r.success ? 'OK' : 'FAIL'}: ${r.message}`)
            .join('\n')
          audit.record({
            tool: 'tm_rollback',
            category: 'rollback',
            decision: 'allow',
            reason: `Rolled back last operation (${lastWrite.tool})`,
            targetPaths: paths,
            snapshotId: snapDate,
          })
          return `Rolled back ${paths.length} path(s) from last operation:\n${summary}`
        }

        // Roll back explicit path
        if (!args.path) {
          return 'Error: either "path" or "last_operation=true" must be provided.'
        }
        const result: RollbackResult = await rollbackPath(
          args.path,
          args.snapshot_date,
        )
        audit.record({
          tool: 'tm_rollback',
          category: 'rollback',
          decision: 'allow',
          reason: result.message,
          targetPaths: [args.path],
          snapshotId: result.snapshotUsed,
        })
        return result.message
      },
    }),
  )

  // --- tm_audit: review operation history ---
  ctx.tools.register(
    defineTool({
      name: 'tm_audit',
      description:
        'Review the TM-Guard audit log — every tool call that was allowed or blocked, ' +
        'with target paths and snapshot IDs. Use to trace what changes were made, ' +
        'find the snapshot ID for a specific operation, or verify what was blocked.',
      parameters: {
        limit: {
          type: 'number',          description:
            'Number of recent records to show (default 20, max 100).',
        },
        only_writes: {
          type: 'boolean',          description:
            'If true, only show file-modification operations (for rollback targeting).',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: { limit?: number; only_writes?: boolean }) {
        const limit = Math.min(args.limit ?? 20, 100)
        const records = args.only_writes
          ? audit.writeOperations().slice(-limit)
          : audit.recent(limit)

        if (records.length === 0) {
          return 'No audit records found.'
        }

        const lines = records.map((r) => {
          const time = new Date(r.ts).toLocaleTimeString()
          const decision = r.decision === 'allow' ? 'ALLOW' : 'BLOCK'
          const paths = r.targetPaths.length > 0
            ? ` [${r.targetPaths.join(', ')}]`
            : ''
          const snap = r.snapshotId ? ` snap=${r.snapshotId}` : ''
          return `  ${time} ${decision} [${r.category}] ${r.tool}${paths}${snap}`
        })

        const header = `=== TM-Guard Audit Log (${records.length} records, log: ${audit.path}) ===`
        return `${header}\n${lines.join('\n')}`
      },
    }),
  )

  // --- tm_git_bloat: read-only .git size diagnosis ---
  ctx.tools.register(
    defineTool({
      name: 'tm_git_bloat',
      description:
        'READ-ONLY diagnosis of what makes a .git directory large: ranks the biggest ' +
        'reachable blobs, and for each shows the path and the commit that introduced it. ' +
        'Use when a repo is slow to clone or its .git has grown unexpectedly. ' +
        'READ-ONLY: it never rewrites history, deletes objects, or runs gc/prune/filter-repo/BFG ' +
        '— cleanup is a manual, destructive decision you must make yourself (see README). ' +
        'Returns a clear message (not an error) when the target is not a git repository.',
      parameters: {
        top: {
          type: 'number',
          description: `How many blobs to rank (default ${BLOAT_TOP_N}, max 100).`,
        },
        path: {
          type: 'string',
          description:
            'Directory inside the repository to analyse (default: the workspace cwd).',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: { top?: number; path?: string }) {
        const top = Math.max(1, Math.min(args.top ?? BLOAT_TOP_N, 100))
        const target = args.path && args.path.trim() ? resolve(args.path) : process.cwd()
        return diagnoseGitBloat(target, { topN: top })
      },
    }),
  )

  // --- tm_status: system health check ---
  ctx.tools.register(
    defineTool({
      name: 'tm_status',
      description:
        'Check Time Machine configuration, available snapshots, workspace protection ' +
        'status, and current TM-Guard policy. Run this first to confirm the safety net is active.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        const status = await getTmStatus()
        const latest = await latestSnapshot('/')
        const health = await getTmHealth(config.protectedPaths, true)
        // One full parse, not two (design §4.4.2). `writeOperations()` internally
        // calls readAll() again, so the old pairing parsed the whole retained
        // history twice per tm_status.
        const all = audit.readAll()
        const auditCount = all.length
        const writeCount = all.filter(
          (r) => r.decision === 'allow' && r.targetPaths.length > 0,
        ).length
        // Recent decisions come from the parsed array, not `audit.recent()`,
        // which would re-read every generation a third time.
        const recentDecisions = all
          .filter((r) => r.decision === 'allow' || r.decision === 'deny')
          .slice(-RECENT_STATUS_ITEMS)
          .reverse()

        return renderStatusReport({
          platformSupported,
          platform: process.platform,
          health,
          status,
          latest,
          config,
          audit,
          auditCount,
          writeCount,
          recentDecisions,
        })
      },
    }),
  )

  // --- tm_backup: trigger a backup to the TM disk (SD) ---
  ctx.tools.register(
    defineTool({
      name: 'tm_backup',
      description:
        'Start a Time Machine backup to the configured backup disk (e.g. the SD card). ' +
        'Finishing a backup creates a fresh, browsable restore point — call this after a ' +
        'batch of changes if you want a newer rollback point than the hourly automatic one. ' +
        'By default starts in the BACKGROUND and returns immediately; set wait=true to block ' +
        'until the backup completes (may take minutes).',
      parameters: {
        wait: {
          type: 'boolean',
          description:
            'If true, block until the backup finishes before returning. Default false (fire and forget).',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: { wait?: boolean }) {
        const wait = args.wait === true
        try {
          await startBackup(wait)
          if (wait) {
            invalidateHealthCache()
            const snap = await latestSnapshot('/')
            const restoreId = snap?.date
            audit.record({
              tool: 'tm_backup',
              category: 'snapshot',
              decision: 'allow',
              reason: 'Blocking backup completed — rollback restore point',
              targetPaths: [],
              snapshotId: restoreId,
            })
            return restoreId
              ? `Time Machine backup completed. Checkpoint: ${restoreId} (on the backup disk). ` +
                `You can now modify files. If verification fails, call tm_rollback to recover; command-line ` +
                `restore from this exact point may briefly need the Time Machine UI (macOS mounts completed ` +
                `backups lazily), after which it is root-free.`
              : 'Time Machine backup completed. Use tm_list_snapshots / tm_audit to find a point to roll back to.'
          }
          audit.record({
            tool: 'tm_backup',
            category: 'snapshot',
            decision: 'allow',
            reason: 'Backup triggered (background)',
            targetPaths: [],
          })
          return 'Time Machine backup started in the background. Use tm_backup_status to watch progress; ' +
            'a browsable restore point appears once it finishes (then tm_rollback can use it).'
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          audit.record({
            tool: 'tm_backup',
            category: 'snapshot',
            decision: 'allow',
            reason: `Backup trigger failed: ${msg}`,
            targetPaths: [],
          })
          return `Failed to start Time Machine backup: ${msg}. Check the backup disk (SD) is connected (see tm_status).`
        }
      },
    }),
  )

  // --- tm_backup_status: backup progress ---
  ctx.tools.register(
    defineTool({
      name: 'tm_backup_status',
      description:
        'Show the current Time Machine backup progress — whether a backup is running, ' +
        'the percent complete, and the current phase. Use after tm_backup to confirm it finished.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        try {
          const st = await getBackupStatus()
          audit.record({
            tool: 'tm_backup_status',
            category: 'read',
            decision: 'allow',
            reason: `Backup status: running=${st.running}`,
            targetPaths: [],
          })
          if (st.running) {
            const pct = st.percent >= 0 ? `${st.percent}%` : 'progress unknown'
            const phase = st.phase ? `, phase: ${st.phase}` : ''
            return `Backup in progress: ${pct}${phase}.`
          }
          return 'No backup currently running. The last backup has completed (a browsable restore point is available).'
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          return `Could not read backup status: ${msg}`
        }
      },
    }),
  )

  if (config.verbose) {
    console.log(
      `[tm-guard] Loaded. Protected paths: ${config.protectedPaths.join(', ')}. ` +
      `Audit log: ${audit.path}. ` +
      `Deny-read paths: ${config.denyReadPaths.join(', ') || '(none)'}`,
    )
  }
}
