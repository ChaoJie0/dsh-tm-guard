/**
 * First-run safety baseline self-check (U-27).
 *
 * The problem this solves is a matching problem, not a missing feature: every
 * fact the report contains was already reachable — `tm_status` prints the TM
 * health, `tmutil destinationinfo` prints the destination, the source shows
 * the deny list. But the user has to *ask*, and each answer is a snapshot of a
 * single moment that leaves nothing behind. So the question a new install
 * actually raises — "what protection level am I in right now?" — had no
 * artifact answering it. A safety tool whose honest boundaries live only in a
 * README section the user may never scroll to is, from the user's side,
 * indistinguishable from one that claims blanket protection.
 *
 * The fix: on the FIRST `apply()` (no `.tm-guard/baseline-report.md` yet),
 * probe the machine once and write down what is actually true — TM configured,
 * workspace protected, git baseline creatable, how many deny-read entries are
 * live, which platform mode is in effect — followed by the residual risks that
 * remain even when everything above is green. The README's Limitations become
 * facts measured on *this* machine. The report then stays on disk (§
 * baseline-report.md) and every later `apply()` is a single `existsSync`.
 *
 * Read-only by construction. The one probe that must *understand* git
 * (`rev-parse`) does not create anything, and the git baseline probe
 * deliberately does NOT call `ensureGitBaseline` — that function runs
 * `git init` + a commit, which would mutate the user's workspace during plugin
 * load. "Can a baseline be built here?" is answered with `rev-parse` plus an
 * `existsSync` on `.git`, and the report says plainly that creation happens
 * lazily at the first write. See `docs/` for the U-27 design note.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { getTmStatus, getTmHealth } from './tm.ts'
import { probeGitSync } from './git.ts'

/** File name of the first-run report, relative to `.tm-guard/`. */
export const BASELINE_REPORT_FILE = 'baseline-report.md'

/**
 * The six section headings, in order. Exported as data (not just written into
 * the markdown) so the test suite and `tm_status` can anchor on the same list
 * instead of duplicating literals that would silently drift apart.
 */
export const BASELINE_SECTIONS = [
  '## 1. Time Machine 配置',
  '## 2. Workspace 保护状态',
  '## 3. Git baseline 可建性',
  '## 4. denyReadPaths 实际生效项',
  '## 5. 平台支持状态',
  '## 6. 已知残余风险',
] as const

/**
 * Residual risks quoted from README § "Limitations & honest scope". They are
 * repeated here on purpose: a user who never opens the README still needs to
 * know that a green report is not a statement of isolation.
 */
export const README_LIMITATION_REFERENCES = [
  'README.md#limitations--honest-scope',
  'README.md#platform-support',
  'README.md#auto-approval-and-its-blast-radius',
] as const

/** Result of probing whether a local git baseline is reachable at `cwd`. */
export interface GitBaselineProbe {
  /** A git binary responded to `rev-parse` in this directory. */
  repo: boolean
  /** Work-tree root, when `cwd` is inside a repository. */
  root: string | null
  /** Whether a `.git` directory is present at (or above) the work tree root. */
  hasGitDir: boolean
  /** Whether a `git` binary was found at all (false = not installed / not on PATH). */
  gitAvailable: boolean
}

/**
 * Time Machine facts for the report.
 *
 * `probed: false` is NOT the same as "TM is unhealthy": on a non-macOS host
 * there is no tmutil to ask, so the report must say "not applicable" rather
 * than render an unconfigured destination as a fault the user should chase.
 */
export interface TmBaselineFacts {
  probed: boolean
  destinationConfigured: boolean
  healthy: boolean
  workspaceProtected: boolean
  unprotectedPaths: string[]
}

export interface BaselineReportInput {
  /** `process.platform` on the host that ran apply(). */
  platform: string
  /** False on non-macOS hosts (U-19): TM cannot exist, plugin runs limited. */
  platformSupported: boolean
  /** Absolute workspace root the report describes. */
  workspace: string
  /** Where the report is written (absolute path of baseline-report.md). */
  reportPath: string
  /** Effective `denyReadPaths` after the additive merge. */
  denyReadPaths: string[]
  /** Effective writable scope. */
  protectedPaths: string[]
  /** Append (`false`) or replace (`true`) semantics for denyReadPaths. */
  denyReadPathsReplace: boolean
  /** Effective gate settings worth pinning in the report. */
  failClosed: boolean
  autoApprove: boolean
  requireGitBaseline: boolean
  /** `tmutil` probe outcome (see TmBaselineFacts). */
  tm: TmBaselineFacts
  /** Git baseline reachability at the workspace. */
  git: GitBaselineProbe
  /** When the report was generated. */
  generatedAt: Date
}

/** Markdown table cell: pipes and newlines would break the row layout. */
function cell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim()
}

/** `YES ✅` / `NO ⚠️` — the one vocabulary the whole report uses. */
function yesNo(ok: boolean, yes = 'YES ✅', no = 'NO ⚠️'): string {
  return ok ? yes : no
}

/**
 * Probe whether a git baseline can be built at `dir` — WITHOUT building it.
 *
 * The actual subprocess lives in git.ts (`probeGitSync`) so that the one
 * read-only git command in this plugin shares the module's test seam. This
 * wrapper only adds the `.git`-presence check and shapes the result for the
 * report. Never throws.
 */
export function probeGitBaseline(dir: string): GitBaselineProbe {
  const { gitAvailable, root } = probeGitSync(dir)
  const gitDir = root ?? dir
  return {
    repo: root !== null,
    root,
    hasGitDir: existsSync(join(gitDir, '.git')),
    gitAvailable,
  }
}

/**
 * Render the report. Pure: same input ⇒ same output, no filesystem access.
 * Kept separate from the probing so tests can pin the wording (including the
 * non-macOS `limited mode` labelling) without touching tmutil or git.
 */
export function renderBaselineReport(input: BaselineReportInput): string {
  const { git, denyReadPaths, workspace, platform, platformSupported } = input
  const out: string[] = []

  out.push('# TM-Guard 首次运行安全基线自检')
  out.push('')
  out.push(
    '这份报告在插件**首次加载**时自动生成，落盘保存。它记录的是**这台机器此刻的实际保护等级**，',
  )
  out.push(
    '而不是插件的能力上限——两者经常不一致，`tm_status` 只在被调用时给出同一类事实的单次快照。',
  )
  out.push('')
  out.push('| 项 | 值 |')
  out.push('|---|---|')
  out.push(`| 生成时间 | ${input.generatedAt.toISOString()} |`)
  out.push(`| 平台 | ${cell(platform)}${platformSupported ? '（full mode）' : '（limited mode — 无 Time Machine）'} |`)
  out.push(`| Workspace | ${cell(workspace)} |`)
  out.push(`| 报告路径 | ${cell(input.reportPath)} |`)
  out.push(
    '| 说明 | 只读探测：本报告生成过程不写 git、不改配置、不创建快照 |',
  )

  /* --- 1. Time Machine ------------------------------------------- */
  out.push('', BASELINE_SECTIONS[0])
  if (!platformSupported) {
    out.push('')
    out.push(
      `  TM 不适用：当前平台 \`${cell(platform)}\` 没有 \`/usr/bin/tmutil\`，` +
      '无法配置 Time Machine 备份目的地。这一项是**能力限制**，不是故障。',
    )
  } else if (!input.tm.probed) {
    out.push('')
    out.push(
      '  TM 探测未完成：加载时 tmutil 未在超时内响应。' +
      '这一项**未知**，不能读作「已配置」——用 `tm_status` 重新确认。',
    )
    out.push('  → 下一步：手动运行 `tmutil destinationinfo` 与 `tmutil listlocalsnapshots /`。')
  } else {
    const { tm } = input
    out.push('')
    out.push(`  TM 已配置（tmutil destinationinfo）：${yesNo(tm.destinationConfigured, 'YES ✅', 'NO ⚠️')}`)
    out.push(`  Workspace 受 TM 保护          ：${yesNo(tm.workspaceProtected)}`)
    out.push(`  TM 整体健康（fail-closed 依据）：${yesNo(tm.healthy, 'HEALTHY ✅', 'UNHEALTHY 🚫 — 写入会被拦截')}`)
    if (tm.unprotectedPaths.length > 0) {
      out.push(`  未受保护的路径                ：${cell(tm.unprotectedPaths.join(', '))}`)
    }
    if (!tm.destinationConfigured) {
      out.push('')
      out.push('  → 下一步：系统设置 → 通用 → 时间机器，选择备份磁盘，然后重开一个会话。')
    }
  }

  /* --- 2. Workspace protection ----------------------------------- */
  out.push('', BASELINE_SECTIONS[1])
  out.push('')
  out.push(`  受保护（可写）路径 ${input.protectedPaths.length} 条：${cell(input.protectedPaths.join(', ')) || '(none)'}`)
  if (input.protectedPaths.length === 0) {
    out.push('  ⚠️  没有任何可写路径——每一次写入都会被拒绝。请检查 protectedPaths 配置。')
  }
  out.push(
    `  TM 层面已保护               ：${
      !platformSupported
        ? 'N/A（无 TM，见第 5 节）'
        : input.tm.probed
          ? yesNo(input.tm.workspaceProtected)
          : '未知（TM 探测未完成）'
    }`,
  )
  if (platformSupported && input.tm.probed && input.tm.unprotectedPaths.length > 0) {
    out.push(
      `  ⚠️  TM 排除列表命中的路径：${cell(input.tm.unprotectedPaths.join(', '))}——` +
      '这些路径上的写入没有被 Time Machine 覆盖，只剩 git baseline。',
    )
  }
  out.push(
    '  注意：workspace「受保护」= 可写 + 有回滚网，不等于被沙箱隔离。' +
    '见第 6 节与 README § Limitations。',
  )

  /* --- 3. Git baseline ------------------------------------------- */
  out.push('', BASELINE_SECTIONS[2])
  out.push('')
  out.push(`  git 可用（rev-parse 有响应）: ${yesNo(git.gitAvailable, 'YES ✅', 'NO ⚠️ — git 未安装或不在 PATH')}`)
  out.push(`  已在 git 仓库内（work tree）: ${yesNo(git.repo, 'YES ✅', 'NO — 首次写入时会自动 git init')}`)
  if (git.root) out.push(`  work tree 根                : ${cell(git.root)}`)
  out.push(`  .git 目录存在               : ${yesNo(git.hasGitDir, 'YES ✅', 'NO — 首次写入时创建')}`)
  out.push(
    `  requireGitBaseline          : ${yesNo(input.requireGitBaseline, 'YES', 'no')}` +
    `${input.requireGitBaseline ? '（git 不可用时不放行写入）' : '（git 不可用时不额外拦截）'}`,
  )
  out.push(
    '  可建性判定完成，但**本次没有建**：git baseline 在第一次写入时惰性创建' +
    '（`git init` + 一次 baseline commit），因此这次自检是只读的。',
  )
  if (!git.gitAvailable) {
    out.push('  → 下一步：安装 git 并确认它在 PATH 上；否则回滚网只剩 Time Machine（若第 1 节为 YES）。')
  }

  /* --- 4. denyReadPaths ------------------------------------------ */
  out.push('', BASELINE_SECTIONS[3])
  out.push('')
  out.push(`  实际生效项数：${denyReadPaths.length}`)
  out.push(`  合并语义    ：${input.denyReadPathsReplace ? '替换（denyReadPathsReplace=true，默认清单被覆盖）' : '追加（默认清单 + 用户添加项）'}`)
  if (denyReadPaths.length === 0) {
    out.push('  ⚠️  清单为空——agent 可以读取任意路径，包括 SSH 私钥与云凭证。这是显式关闭，不是默认状态。')
  }
  for (const p of denyReadPaths) out.push(`    - ${cell(p)}`)
  out.push(
    '  匹配语义：每个条目是**前缀**（`~/.ssh` 覆盖 `~/.ssh/id_rsa`），读和写两个方向都被拒绝。',
  )

  /* --- 5. Platform ----------------------------------------------- */
  out.push('', BASELINE_SECTIONS[4])
  out.push('')
  if (platformSupported) {
    out.push(`  ${cell(platform)} — full mode（Time Machine 可用）`)
    out.push(
      '  快照 / 回滚 / fail-closed TM 检查全部按 macOS 路径工作；' +
      '`tm_*` 工具在此平台有效。',
    )
  } else {
    out.push(`  ${cell(platform)} — **limited mode（无 TM）**`)
    out.push(
      '  没有 tmutil，因此：`tm_snapshot` / `tm_rollback` / `tm_backup` 等工具不可用，' +
      'fail-closed 的 TM 检查不会拦截写入（没有可检查的对象）。',
    )
    out.push(
      '  唯一的回滚网是**本地 git baseline**：每个任务写入前先 commit 一个检查点，' +
      '失败时用 `git reset --hard` + `git clean -fd` 回滚。',
    )
  }

  /* --- 6. Residual risk ------------------------------------------ */
  out.push('', BASELINE_SECTIONS[5])
  out.push('')
  out.push('  即使上面全部为 ✅，以下残余风险依然存在（引自 README Limitations，逐条对照本机）：')
  out.push('')
  out.push('  1. **eval / decode 逃逸**：静态外发扫描是正则文本分析，不是执行追踪，')
  out.push('     不是内核级沙箱。运行时拼接的字符串、动态 decode 后执行的代码、')
  out.push('     藏在 Makefile / cargo run 后面的目标都扫不到。')
  out.push('  2. **运行时 URL**：只有字面量 URL 会被识别；由变量、环境变量或配置文件')
  out.push('     拼出来的目标地址不在静态扫描范围内。')
  out.push('  3. **与其他权限插件叠加语义**：`autoApprove=true` 时本插件替你应答 approval，')
  out.push('     其安全性依赖本插件以 `prepend` 顺序注册（先分类、先拒绝）。')
  out.push('     若另一个权限插件注册更早或绕过该瀑布，操作可能在**未被检查**的情况下被自动放行，')
  out.push('     而本插件无法校验它控制不到的插件顺序。')
  out.push('  4. **不是沙箱**：插件以 DSH 宿主进程的权限运行，只检查经宿主路由过来的工具调用，')
  out.push('     不约束 syscall。本机加固请叠加外部防火墙 / 一次性 profile / VM 与最小权限凭证。')
  out.push('  5. **路径与命令分类是启发式的**：写法冷门的单行命令可能被误分类；')
  out.push('     未识别的默认拒绝（保守方向），但请以 `denyNetwork` 作为出口兜底。')
  out.push('')
  out.push('  权威表述见：')
  for (const ref of README_LIMITATION_REFERENCES) out.push(`    - ${ref}`)
  out.push('')
  out.push('---')
  out.push('')
  out.push(`本报告只在首次运行生成一次（${BASELINE_REPORT_FILE} 存在即跳过）。`)
  out.push('要看**当前**状态用 `tm_status`；要重新生成本报告，删除该文件后重启会话。')
  out.push('')

  return out.join('\n')
}

/**
 * The placeholder written when the report has to go to disk before the
 * asynchronous tmutil probe has answered.
 *
 * Why a placeholder rather than waiting: the report must exist the moment
 * apply() returns. Consumers read it (and tests assert it) as soon as the
 * plugin is loaded, and a "first-run report" that appears a second later is
 * indistinguishable from one that never appears. The git probe is synchronous,
 * so there is no reason to publish a half-blank file — only the TM section has
 * to be filled in later. `probed: false` renders as an explicit "unknown, do
 * not read as configured" rather than as an unconfigured destination.
 */
export const UNPROBED_TM: TmBaselineFacts = {
  probed: false,
  destinationConfigured: false,
  healthy: false,
  workspaceProtected: false,
  unprotectedPaths: [],
}

export interface BaselineWriteResult {
  written: boolean
  reportPath: string
  markdown: string
  error?: string
}

/**
 * Write the report if it does not exist yet — synchronously.
 *
 * Returns `{ written: false }` with the existing path in the steady state,
 * which is the entire cost of this feature on every apply() after the first
 * (one `existsSync`).
 *
 * Never throws: this runs at plugin load, and a report that cannot be written
 * must not stop the gate from loading (design R6 — the same rule report
 * pruning follows). Failures come back in the return value so `apply()` can
 * degrade to a warning.
 */
export function ensureBaselineReport(
  dir: string,
  input: Omit<BaselineReportInput, 'reportPath'>,
): BaselineWriteResult {
  const reportPath = join(dir, BASELINE_REPORT_FILE)
  if (existsSync(reportPath)) {
    return { written: false, reportPath, markdown: '' }
  }
  const markdown = renderBaselineReport({ ...input, reportPath })
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(reportPath, markdown, 'utf8')
    return { written: true, reportPath, markdown }
  } catch (err) {
    return {
      written: false,
      reportPath,
      markdown,
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

/**
 * Fill in the TM section once the asynchronous probe answers.
 *
 * A single read-check-write, deliberately WITHOUT the "does it exist" first-run
 * gate: by the time this runs, `ensureBaselineReport` has already decided that
 * this workspace's first run is happening. If the file is gone by now (the user
 * deleted it mid-load) the rewrite is exactly what the next apply() would have
 * done anyway, so this cannot resurrect a report the user wanted gone for longer
 * than one load.
 *
 * Returns whether the on-disk bytes actually changed, so the caller can keep
 * the first-run notice honest.
 */
export function refineBaselineReportTm(
  reportPath: string,
  input: Omit<BaselineReportInput, 'reportPath'>,
): boolean {
  try {
    if (!existsSync(reportPath)) return false
    const before = readFileSync(reportPath, 'utf8')
    const after = renderBaselineReport({ ...input, reportPath, tm: input.tm })
    if (after === before) return false
    writeFileSync(reportPath, after, 'utf8')
    return true
  } catch {
    // A refinement failure leaves the placeholder in place, which already says
    // "unknown — check tm_status". Nothing to escalate.
    return false
  }
}

/**
 * Synchronous part of the fact gathering: everything except TM.
 *
 * Only the git probe is synchronous by design — it is one `git rev-parse` with
 * a 10s timeout, and it never mutates the repository. See
 * `collectTmBaselineFacts` for the async half.
 */
export function collectSyncBaselineFacts(workspace: string): { git: GitBaselineProbe } {
  return { git: probeGitBaseline(workspace) }
}

/**
 * Asynchronous TM half of the fact gathering, in one read-only pass.
 *
 * On a non-macOS host every tmutil call is a guaranteed failure, and letting
 * them fail noisily is exactly what U-19 removed — so the probe is skipped and
 * the result is reported as not-applicable. Never throws: a probe that cannot
 * complete yields `probed: false`, which the renderer prints as "unknown".
 */
export async function collectTmBaselineFacts(opts: {
  platform: string
  protectedPaths: string[]
}): Promise<TmBaselineFacts> {
  if (opts.platform !== 'darwin') return { ...UNPROBED_TM }
  let destinationConfigured = false
  try {
    const s = await getTmStatus()
    destinationConfigured = s.destinationConfigured
  } catch {
    // tmutil unavailable/failing is itself a finding — it renders as NO ⚠️.
  }
  let healthy = false
  let workspaceProtected = false
  let unprotectedPaths: string[] = []
  try {
    const h = await getTmHealth(opts.protectedPaths, true)
    healthy = h.healthy
    workspaceProtected = h.workspaceProtected
    unprotectedPaths = h.unprotectedPaths
  } catch {
    // Same: an unknown health is reported as not-healthy, never as healthy.
  }
  return {
    probed: true,
    destinationConfigured,
    healthy,
    workspaceProtected,
    unprotectedPaths,
  }
}
